/*
obs-ytsucks - PII redaction filter for OBS Studio
Copyright (C) 2026 obs-ytsucks contributors

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>
*/

// "PII Redaction (OCR)" video filter.
//
// Render thread (video_render):
//   1. Renders the filter's input into a ring of textures (one per frame of
//      configured delay).
//   2. Every `interval` ms copies the newest frame to a staging surface and,
//      one frame later, maps it and hands the pixels to the analysis thread.
//   3. Draws the frame from `delay` frames ago and covers every region the
//      tracker says belongs to it (box / pixelate / blur).
//
// Analysis thread:
//   frame split into overlapping horizontal bands; unchanged bands reuse
//   their previous result, the rest are OCR'd in parallel (OcrPool, one
//   engine per thread) -> PiiMatcher -> scan result.
//
// Motion thread:
//   Receives a small grey thumbnail every few frames (more often while
//   content moves, always for the frame OCR scanned) plus the scan results,
//   and runs MotionTracker: boxes follow scrolling content, are extrapolated
//   and widened between samples, and late scans are carried forward to where
//   the content is now.

#include "pii-redact-filter.h"

#include "core/image.hpp"
#include "core/pii-matcher.hpp"
#include "core/bands.hpp"
#include "core/motion-tracker.hpp"
#include "ocr/ocr-engine.hpp"
#include "ocr/ocr-pool.hpp"

#include <obs-module.h>
#include <graphics/vec2.h>
#include <graphics/vec4.h>
#include <util/platform.h>
#include <plugin-support.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <deque>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace pii;

namespace {

// ---------------------------------------------------------------------------
// Settings keys
// ---------------------------------------------------------------------------
constexpr const char *S_EMAIL = "detect_email";
constexpr const char *S_PHONE = "detect_phone";
constexpr const char *S_SSN = "detect_ssn";
constexpr const char *S_CARD = "detect_card";
constexpr const char *S_IP = "detect_ip";
constexpr const char *S_ADDRESS = "detect_address";
constexpr const char *S_DOB = "detect_dob";
constexpr const char *S_SECRETS = "detect_secrets";
constexpr const char *S_KEYWORDS = "keywords";
constexpr const char *S_REGEX = "custom_regex";
constexpr const char *S_STYLE = "style";
constexpr const char *S_COLOR = "color";
constexpr const char *S_STRENGTH = "strength";
constexpr const char *S_PADDING = "padding";
constexpr const char *S_PERSIST = "persist_ms";
constexpr const char *S_BACKEND = "ocr_backend";
constexpr const char *S_LANGUAGE = "ocr_language";
constexpr const char *S_TESSDATA = "tessdata_path";
constexpr const char *S_FAST = "ocr_fast";
constexpr const char *S_INTERVAL = "interval_ms";
constexpr const char *S_SCALE = "ocr_scale";
constexpr const char *S_THREADS = "ocr_threads";
constexpr const char *S_MINCONF = "min_confidence";
constexpr const char *S_DELAY = "delay_frames";
constexpr const char *S_FAILSAFE = "fail_safe";
constexpr const char *S_DEBUG = "debug_outlines";
constexpr const char *S_EDGE = "edge_guard";
constexpr const char *S_STATUS = "status";

constexpr int kMaxDelayFrames = 120;
constexpr uint32_t kThumbWidth = 512;
// Motion sampling: every Nth frame while static, every Mth while moving.
constexpr uint64_t kSampleEveryStatic = 6;
constexpr uint64_t kSampleEveryMoving = 2;
constexpr size_t kThumbStages = 3;

size_t auto_threads()
{
	const unsigned hw = std::thread::hardware_concurrency();
	if (hw <= 2)
		return 1;
	// Leave room for OBS itself and the encoder.
	return std::min<size_t>(8, static_cast<size_t>(hw) * 3 / 4);
}

enum class Style : int { Box = 0, Pixelate = 1, Blur = 2 };

std::vector<std::string> split_lines(const char *text)
{
	std::vector<std::string> out;
	if (!text)
		return out;
	std::istringstream ss(text);
	std::string line;
	while (std::getline(ss, line)) {
		while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
			line.pop_back();
		size_t start = line.find_first_not_of(" \t");
		if (start == std::string::npos)
			continue;
		out.push_back(line.substr(start));
	}
	return out;
}

std::string bundled_tessdata_path()
{
	char *path = obs_module_file("tessdata");
	std::string out = path ? path : "";
	bfree(path);
	return out;
}

// Settings the render thread needs every frame.
struct RenderSettings {
	Style style = Style::Box;
	uint32_t color = 0xFF000000; // ABGR as stored by OBS
	float strength = 16.0f;
	int delay_frames = 0;
	bool fail_safe = false;
	bool debug = false;
	bool edge_guard = true;
	uint64_t interval_ns = 250000000ULL;
};

// Settings the analysis thread needs.
struct AnalysisSettings {
	MatcherConfig matcher;
	OcrConfig ocr;
	double scale = 1.0;
	int padding = 6;
	size_t threads = 1;
};

struct MotionEvent {
	enum class Kind { Frame, Scan } kind = Kind::Frame;
	uint64_t seq = 0;
	uint64_t ts = 0;
	Image thumb; // BGRA (Frame)
	uint32_t full_w = 0;
	uint32_t full_h = 0;
	std::vector<Rect> rects; // (Scan)
};

struct Job {
	uint64_t seq = 0;
	uint64_t ts = 0;
	Image image;
};

struct Slot {
	gs_texrender_t *texrender = nullptr;
	uint64_t seq = 0;
	uint64_t ts = 0;
	bool valid = false;
};

class PiiRedactFilter {
public:
	explicit PiiRedactFilter(obs_source_t *source);
	~PiiRedactFilter();

	void update(obs_data_t *settings);
	void tick() { capture_pending_ = true; }
	void render();
	obs_properties_t *properties();

	void toggle_panic() { panic_ = !panic_; }

private:
	// render thread helpers
	void reset_ring(uint32_t width, uint32_t height, size_t slots);
	void free_graphics();
	bool capture(Slot &slot, uint32_t width, uint32_t height);
	// Returns true when this frame was staged for OCR.
	bool schedule_analysis(const Slot &slot, const RenderSettings &rs);
	void sample_motion(const Slot &slot, bool force);
	void draw_texture(gs_texture_t *tex, uint32_t width, uint32_t height);
	void draw_solid(const std::vector<Rect> &rects, uint32_t color);
	void draw_filtered(gs_texture_t *tex, const std::vector<Rect> &rects, const RenderSettings &rs, uint32_t width,
			   uint32_t height);
	void draw_outlines(const std::vector<Rect> &rects);

	// analysis thread
	void worker_main();
	// motion thread
	void motion_main();
	void post_motion(MotionEvent ev);

	void set_status(const std::string &s);

	obs_source_t *context_;
	gs_effect_t *redact_effect_ = nullptr;

	// Render-thread state (graphics context only).
	std::vector<Slot> ring_;
	size_t write_idx_ = 0;
	uint64_t frame_seq_ = 0;
	uint32_t width_ = 0;
	uint32_t height_ = 0;
	gs_stagesurf_t *stage_ = nullptr;
	bool stage_pending_ = false;
	uint64_t stage_seq_ = 0;
	uint64_t stage_ts_ = 0;
	uint64_t last_stage_ns_ = 0;
	std::atomic<bool> capture_pending_{true};
	std::atomic<bool> panic_{false};

	std::mutex settings_mutex_;
	RenderSettings render_settings_;
	AnalysisSettings analysis_settings_;
	uint64_t analysis_generation_ = 0;

	// Worker
	std::thread worker_;
	std::mutex job_mutex_;
	std::condition_variable job_cv_;
	bool job_ready_ = false;
	bool stopping_ = false;
	Job job_;
	std::atomic<bool> worker_busy_{false};

	// Motion sampling (render thread)
	gs_texrender_t *thumb_tr_ = nullptr;
	gs_stagesurf_t *thumb_stage_[kThumbStages] = {};
	bool thumb_pending_[kThumbStages] = {};
	uint64_t thumb_seq_[kThumbStages] = {};
	uint64_t thumb_ts_[kThumbStages] = {};
	size_t thumb_next_ = 0;
	uint32_t thumb_w_ = 0;
	uint32_t thumb_h_ = 0;
	uint64_t last_sample_seq_ = 0;

	// Motion thread
	std::thread motion_thread_;
	std::mutex motion_mutex_;
	std::condition_variable motion_cv_;
	std::deque<MotionEvent> motion_queue_;
	bool motion_stopping_ = false;
	std::atomic<bool> moving_{false};
	std::atomic<bool> force_scan_{false};
	std::atomic<uint64_t> persist_ns_{1500000000ULL};
	std::atomic<int> delay_frames_{0};
	std::atomic<double> speed_px_s_{0.0};
	std::atomic<size_t> track_count_{0};
	// Page scroll measured by the scans (full-res px per video frame, + = down),
	// the frame it was measured on, and a line height, for the edge guard.
	std::atomic<double> scroll_vy_{0.0};
	std::atomic<uint64_t> scroll_seq_{0};
	std::atomic<int> line_px_{48};
	std::atomic<uint64_t> latency_frames_{2};

	std::mutex view_mutex_;
	std::shared_ptr<const TrackerView> view_;

	std::mutex status_mutex_;
	std::string status_ = "Waiting for first frame...";
};

// ---------------------------------------------------------------------------

PiiRedactFilter::PiiRedactFilter(obs_source_t *source) : context_(source)
{
	char *path = obs_module_file("effects/redact.effect");
	if (path) {
		obs_enter_graphics();
		char *errors = nullptr;
		redact_effect_ = gs_effect_create_from_file(path, &errors);
		obs_leave_graphics();
		if (!redact_effect_)
			obs_log(LOG_ERROR, "failed to load %s: %s", path, errors ? errors : "(no details)");
		bfree(errors);
		bfree(path);
	}

	worker_ = std::thread(&PiiRedactFilter::worker_main, this);
	motion_thread_ = std::thread(&PiiRedactFilter::motion_main, this);
}

PiiRedactFilter::~PiiRedactFilter()
{
	{
		std::lock_guard<std::mutex> lock(job_mutex_);
		stopping_ = true;
	}
	job_cv_.notify_all();
	if (worker_.joinable())
		worker_.join();
	{
		std::lock_guard<std::mutex> lock(motion_mutex_);
		motion_stopping_ = true;
	}
	motion_cv_.notify_all();
	if (motion_thread_.joinable())
		motion_thread_.join();

	obs_enter_graphics();
	free_graphics();
	if (redact_effect_)
		gs_effect_destroy(redact_effect_);
	obs_leave_graphics();
}

void PiiRedactFilter::update(obs_data_t *settings)
{
	RenderSettings rs;
	rs.style = static_cast<Style>(obs_data_get_int(settings, S_STYLE));
	rs.color = static_cast<uint32_t>(obs_data_get_int(settings, S_COLOR)) | 0xFF000000u;
	rs.strength = static_cast<float>(obs_data_get_double(settings, S_STRENGTH));
	rs.delay_frames = std::clamp(static_cast<int>(obs_data_get_int(settings, S_DELAY)), 0, kMaxDelayFrames);
	rs.fail_safe = obs_data_get_bool(settings, S_FAILSAFE);
	rs.debug = obs_data_get_bool(settings, S_DEBUG);
	rs.edge_guard = obs_data_get_bool(settings, S_EDGE);
	rs.interval_ns =
		static_cast<uint64_t>(std::max<long long>(0, obs_data_get_int(settings, S_INTERVAL))) * 1000000ULL;

	AnalysisSettings as;
	as.matcher.email = obs_data_get_bool(settings, S_EMAIL);
	as.matcher.phone = obs_data_get_bool(settings, S_PHONE);
	as.matcher.ssn = obs_data_get_bool(settings, S_SSN);
	as.matcher.credit_card = obs_data_get_bool(settings, S_CARD);
	as.matcher.ip_address = obs_data_get_bool(settings, S_IP);
	as.matcher.street_address = obs_data_get_bool(settings, S_ADDRESS);
	as.matcher.date_of_birth = obs_data_get_bool(settings, S_DOB);
	as.matcher.secrets = obs_data_get_bool(settings, S_SECRETS);
	as.matcher.keywords = split_lines(obs_data_get_string(settings, S_KEYWORDS));
	as.matcher.custom_patterns = split_lines(obs_data_get_string(settings, S_REGEX));
	as.matcher.min_confidence = static_cast<float>(obs_data_get_double(settings, S_MINCONF));
	as.ocr.backend = ocr_backend_from_id(obs_data_get_string(settings, S_BACKEND));
	as.ocr.language = obs_data_get_string(settings, S_LANGUAGE);
	as.ocr.tessdata_path = obs_data_get_string(settings, S_TESSDATA);
	if (as.ocr.tessdata_path.empty())
		as.ocr.tessdata_path = bundled_tessdata_path();
	as.ocr.fast_mode = obs_data_get_bool(settings, S_FAST);
	as.scale = std::clamp(obs_data_get_double(settings, S_SCALE), 0.25, 3.0);
	as.padding = static_cast<int>(obs_data_get_int(settings, S_PADDING));
	const long long threads = obs_data_get_int(settings, S_THREADS);
	as.threads = threads <= 0 ? auto_threads() : static_cast<size_t>(std::min<long long>(threads, 32));

	const uint64_t persist_ns =
		static_cast<uint64_t>(std::max<long long>(0, obs_data_get_int(settings, S_PERSIST))) * 1000000ULL;

	{
		std::lock_guard<std::mutex> lock(settings_mutex_);
		render_settings_ = rs;
		analysis_settings_ = std::move(as);
		analysis_generation_++;
	}
	persist_ns_ = persist_ns;
	delay_frames_ = rs.delay_frames;
}

void PiiRedactFilter::set_status(const std::string &s)
{
	std::lock_guard<std::mutex> lock(status_mutex_);
	status_ = s;
}

// ---------------------------------------------------------------------------
// Analysis thread
// ---------------------------------------------------------------------------

void PiiRedactFilter::worker_main()
{
	std::unique_ptr<OcrPool> pool;
	std::unique_ptr<PiiMatcher> matcher;
	uint64_t generation = UINT64_MAX;
	AnalysisSettings as;
	// Rebuilding the OCR engines is expensive; only do it when their config changed.
	std::string pool_key;
	// Previous scan, for scroll-aware reuse.
	Image prev_sig;
	std::vector<Rect> prev_rects;
	// Per signature row: was it read by OCR with full line context? Rows
	// read right at the frame edge (text possibly cut off) are not, and get
	// re-read once they scroll inwards.
	std::vector<uint8_t> prev_verified;
	uint64_t prev_seq = 0;
	bool prev_valid = false;
	double avg_ms = 0.0;

	for (;;) {
		Job job;
		{
			std::unique_lock<std::mutex> lock(job_mutex_);
			job_cv_.wait(lock, [this] { return job_ready_ || stopping_; });
			if (stopping_)
				break;
			job = std::move(job_);
			job_ready_ = false;
		}

		{
			std::lock_guard<std::mutex> lock(settings_mutex_);
			if (generation != analysis_generation_) {
				generation = analysis_generation_;
				as = analysis_settings_;
				matcher.reset();
			}
		}

		if (!matcher) {
			matcher = std::make_unique<PiiMatcher>(as.matcher);
			for (const std::string &bad : matcher->invalid_patterns())
				obs_log(LOG_WARNING, "ignoring invalid custom regex: %s", bad.c_str());
			prev_valid = false; // detections depend on the matcher settings

			const std::string key = std::string(ocr_backend_id(as.ocr.backend)) + "|" + as.ocr.language +
						"|" + as.ocr.tessdata_path + "|" + (as.ocr.fast_mode ? "1" : "0") +
						"|" + std::to_string(as.threads);
			if (key != pool_key) {
				pool_key = key;
				pool.reset();
				pool = std::make_unique<OcrPool>(as.ocr, as.threads);
				if (pool->ok())
					obs_log(LOG_INFO, "OCR engine: %s x %zu threads", pool->engine_name().c_str(),
						pool->size());
				else
					obs_log(LOG_ERROR, "OCR engine unavailable: %s", pool->error().c_str());
			}
		}

		if (!pool || !pool->ok()) {
			set_status("OCR unavailable: " + (pool ? pool->error() : std::string("not initialised")));
			worker_busy_ = false;
			continue;
		}

		const auto t0 = std::chrono::steady_clock::now();
		const uint32_t src_w = job.image.width;
		const uint32_t src_h = job.image.height;
		Image img = std::move(job.image);
		if (as.scale != 1.0) {
			const uint32_t w = std::max<uint32_t>(1, static_cast<uint32_t>(src_w * as.scale));
			const uint32_t h = std::max<uint32_t>(1, static_cast<uint32_t>(src_h * as.scale));
			img = resize(img, w, h);
		}
		const double back_x = static_cast<double>(src_w) / img.width;
		const double back_y = static_cast<double>(src_h) / img.height;

		// Small overlapping bands (several per OCR thread). The overlap must
		// exceed the tallest line of text we want to catch whole.
		const int ih = static_cast<int>(img.height);
		const int overlap = std::max(40, ih / 18);
		const int band_count = std::max(static_cast<int>(pool->size()), ih / 128);
		const std::vector<Band> bands = plan_bands(ih, band_count, overlap, overlap * 2 + 32);

		// Scroll-aware change detection on a 1/4 size grey copy: a band whose
		// content equals the previous scan's content shifted by the scroll
		// offset (or unshifted) keeps the previous detections, moved by that
		// offset. Only bands with new content are OCR'd, which while
		// scrolling is essentially the strip that just came into view.
		Image sig = to_grey(img);
		sig = resize(sig, std::max<uint32_t>(1, sig.width / 4), std::max<uint32_t>(1, sig.height / 4));
		const double sig_to_img = static_cast<double>(ih) / sig.height;
		const bool have_prev = prev_valid && prev_sig.width == sig.width && prev_sig.height == sig.height;
		const int scroll = have_prev ? estimate_vertical_shift(prev_sig, sig, static_cast<int>(sig.height) / 2)
					     : 0;

		std::vector<Rect> dets; // scaled-image coordinates, unpadded
		std::vector<Image> crops;
		crops.reserve(bands.size());
		std::vector<const Image *> todo;
		std::vector<int> todo_y;
		const int sh = static_cast<int>(sig.height);
		std::vector<uint8_t> verified(static_cast<size_t>(sh), 0);
		const int edge_rows = static_cast<int>(std::ceil(overlap / sig_to_img));
		for (const Band &b : bands) {
			bool reuse = false;
			int shift = 0;
			const int y0 = static_cast<int>(b.y / sig_to_img);
			const int y1 = std::min(sh, static_cast<int>(std::ceil((b.y + b.h) / sig_to_img)));
			if (have_prev) {
				for (int cand : {scroll, 0}) {
					double new_rows = 1.0;
					const double diff = shifted_band_diff(prev_sig, sig, y0, y1, cand, new_rows);
					bool all_verified = new_rows == 0.0;
					for (int y = y0; all_verified && y < y1; y++)
						all_verified = prev_verified[static_cast<size_t>(y - cand)] != 0;
					if (all_verified && diff < 2.0) {
						reuse = true;
						shift = static_cast<int>(std::lround(cand * sig_to_img));
						for (int y = y0; y < y1; y++)
							verified[static_cast<size_t>(y)] = 1;
						break;
					}
					if (cand == 0)
						break;
				}
			}
			if (reuse) {
				for (const Rect &r : prev_rects) {
					Rect m = r;
					m.y += shift;
					const int cy = m.y + m.h / 2;
					if (cy >= b.y && cy < b.y + b.h) {
						m = m.clipped(static_cast<int>(img.width), ih);
						if (!m.empty())
							dets.push_back(m);
					}
				}
				continue;
			}
			crops.push_back(crop(img, Rect{0, b.y, static_cast<int>(img.width), b.h}));
			todo_y.push_back(b.y);
			// Rows this OCR pass reads with full context: the band minus half
			// the overlap at internal edges (the neighbour covers those) and
			// minus a full line height at the frame's top/bottom edge, where
			// text can be cut off.
			// (A slightly smaller margin than half the overlap avoids rounding gaps.)
			const int half = std::max(0, edge_rows / 2 - 2);
			const int v0 = y0 == 0 ? edge_rows : y0 + half;
			const int v1 = y1 >= sh ? sh - edge_rows : y1 - half;
			for (int y = std::max(0, v0); y < std::min(sh, v1); y++)
				verified[static_cast<size_t>(y)] = 1;
		}
		for (const Image &c : crops)
			todo.push_back(&c);

		const std::vector<std::vector<OcrLine>> results = pool->run(todo);

		size_t words = 0;
		for (size_t k = 0; k < results.size(); k++) {
			std::vector<OcrLine> lines = results[k];
			for (OcrLine &l : lines) {
				for (OcrWord &w : l.words)
					w.box.y += todo_y[k];
				words += l.words.size();
			}
			for (const Detection &d : matcher->match(lines))
				dets.push_back(d.box);
		}
		dets = merge_rects(std::move(dets));
		{
			// Scroll speed for the edge guard, from this scan and the last.
			const double scroll_full = scroll * sig_to_img * back_y;
			const uint64_t frames = have_prev && job.seq > prev_seq ? job.seq - prev_seq : 0;
			scroll_vy_ = frames ? scroll_full / static_cast<double>(frames) : 0.0;
			scroll_seq_ = job.seq;
			line_px_ = static_cast<int>(overlap * back_y);
		}
		prev_seq = job.seq;
		prev_rects = dets;
		prev_verified = std::move(verified);
		prev_sig = std::move(sig);
		prev_valid = true;

		std::vector<Rect> rects;
		for (const Rect &d : dets) {
			Rect r = d.scaled(back_x, back_y)
					 .padded(as.padding)
					 .clipped(static_cast<int>(src_w), static_cast<int>(src_h));
			if (!r.empty())
				rects.push_back(r);
		}
		const std::vector<Band> &band_list = bands;
		const size_t ocr_bands = todo.size();
		const size_t redactions = rects.size();

		const std::vector<Rect> debug_rects = rects;
		MotionEvent ev;
		ev.kind = MotionEvent::Kind::Scan;
		ev.seq = job.seq;
		ev.ts = job.ts;
		ev.rects = std::move(rects);
		post_motion(std::move(ev));

		const double ms =
			std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
		// Total latency = time since the frame was captured (staging + OCR).
		const double latency_ms = static_cast<double>(os_gettime_ns() - job.ts) / 1e6;
		{
			// Frames a scan lags behind (for sizing the edge guard).
			obs_video_info ovi;
			double fps = 30.0;
			if (obs_get_video_info(&ovi) && ovi.fps_den)
				fps = static_cast<double>(ovi.fps_num) / ovi.fps_den;
			latency_frames_ = static_cast<uint64_t>(std::ceil(latency_ms * fps / 1000.0)) + 1;
		}
		avg_ms = avg_ms == 0.0 ? ms : avg_ms * 0.8 + ms * 0.2;
		char buf[384];
		snprintf(
			buf, sizeof(buf),
			"%s x%zu: scan %.0f ms (avg %.0f), latency %.0f ms | %zu/%zu bands re-read (scroll %d), %zu words | "
			"%zu redactions, %zu tracked | motion %.0f px/s",
			pool->engine_name().c_str(), pool->size(), ms, avg_ms, latency_ms, ocr_bands, band_list.size(),
			scroll, words, redactions, track_count_.load(), speed_px_s_.load());
		set_status(buf);
		static const bool debug_log = getenv("OBS_PII_DEBUG") != nullptr;
		if (debug_log) {
			std::string list;
			for (const Rect &r : debug_rects)
				list += " [" + std::to_string(r.x) + "," + std::to_string(r.y) + " " +
					std::to_string(r.w) + "x" + std::to_string(r.h) + "]";
			std::string ocr;
			for (int y : todo_y)
				ocr += " " + std::to_string(y);
			obs_log(LOG_INFO, "scan seq=%llu %s | ocr bands at y:%s | rects:%s",
				static_cast<unsigned long long>(job.seq), buf, ocr.c_str(), list.c_str());
		}

		worker_busy_ = false;
	}

	pool.reset();
}

// ---------------------------------------------------------------------------
// Motion thread
// ---------------------------------------------------------------------------

void PiiRedactFilter::post_motion(MotionEvent ev)
{
	{
		std::lock_guard<std::mutex> lock(motion_mutex_);
		motion_queue_.push_back(std::move(ev));
		// Never let a stalled thread pile up thumbnails.
		while (motion_queue_.size() > 64)
			motion_queue_.pop_front();
	}
	motion_cv_.notify_one();
}

void PiiRedactFilter::motion_main()
{
	MotionTracker tracker;
	uint64_t last_ts = 0;
	uint64_t last_seq = 0;

	for (;;) {
		std::deque<MotionEvent> batch;
		{
			std::unique_lock<std::mutex> lock(motion_mutex_);
			motion_cv_.wait(lock, [this] { return motion_stopping_ || !motion_queue_.empty(); });
			if (motion_stopping_)
				break;
			batch.swap(motion_queue_);
		}

		MotionConfig cfg = tracker.config();
		cfg.persist_ns = persist_ns_;
		cfg.lookback_frames = static_cast<uint64_t>(delay_frames_.load()) + 2;
		tracker.set_config(cfg);

		for (MotionEvent &ev : batch) {
			if (ev.kind == MotionEvent::Kind::Frame) {
				tracker.add_frame(ev.seq, ev.ts, to_grey(ev.thumb), ev.full_w, ev.full_h);
				if (ev.seq > last_seq && last_seq) {
					// Video frames per second from the sample timestamps.
					const double dt = static_cast<double>(ev.ts - last_ts) / 1e9;
					const double frames = static_cast<double>(ev.seq - last_seq);
					if (dt > 0)
						speed_px_s_ = tracker.max_speed() * frames / dt;
				}
				last_ts = ev.ts;
				last_seq = ev.seq;
			} else {
				tracker.add_scan(ev.seq, std::move(ev.rects));
			}
		}

		if (tracker.take_rescan_request())
			force_scan_ = true;
		moving_ = tracker.max_speed() > 0.5;
		track_count_ = tracker.track_count();

		// Render needs positions from the oldest frame it may still output.
		const uint64_t newest = tracker.newest_frame_seq();
		const uint64_t keep = static_cast<uint64_t>(delay_frames_.load()) + 8;
		auto view = std::make_shared<const TrackerView>(tracker.view(newest > keep ? newest - keep : 0));
		std::lock_guard<std::mutex> lock(view_mutex_);
		view_ = std::move(view);
	}
}

// ---------------------------------------------------------------------------
// Render thread
// ---------------------------------------------------------------------------

void PiiRedactFilter::free_graphics()
{
	for (Slot &s : ring_)
		gs_texrender_destroy(s.texrender);
	ring_.clear();
	gs_stagesurface_destroy(stage_);
	stage_ = nullptr;
	gs_texrender_destroy(thumb_tr_);
	thumb_tr_ = nullptr;
	for (size_t i = 0; i < kThumbStages; i++) {
		gs_stagesurface_destroy(thumb_stage_[i]);
		thumb_stage_[i] = nullptr;
		thumb_pending_[i] = false;
	}
	if (stage_pending_) {
		// The staged frame will never be handed to the worker.
		stage_pending_ = false;
		worker_busy_ = false;
	}
}

void PiiRedactFilter::reset_ring(uint32_t width, uint32_t height, size_t slots)
{
	free_graphics();
	ring_.resize(slots);
	for (Slot &s : ring_)
		s.texrender = gs_texrender_create(GS_BGRA, GS_ZS_NONE);
	stage_ = gs_stagesurface_create(width, height, GS_BGRA);
	width_ = width;
	height_ = height;
	write_idx_ = 0;

	thumb_w_ = std::min(kThumbWidth, width);
	thumb_h_ = std::max<uint32_t>(1, static_cast<uint32_t>(static_cast<uint64_t>(height) * thumb_w_ / width));
	thumb_tr_ = gs_texrender_create(GS_BGRA, GS_ZS_NONE);
	for (size_t i = 0; i < kThumbStages; i++)
		thumb_stage_[i] = gs_stagesurface_create(thumb_w_, thumb_h_, GS_BGRA);
	last_sample_seq_ = 0;
}

void PiiRedactFilter::sample_motion(const Slot &slot, bool force)
{
	if (!thumb_tr_)
		return;

	// Hand over thumbnails staged on earlier frames (never the one staged
	// this frame: mapping it would stall the GPU).
	for (size_t i = 0; i < kThumbStages; i++) {
		if (!thumb_pending_[i] || thumb_seq_[i] >= slot.seq)
			continue;
		uint8_t *data = nullptr;
		uint32_t linesize = 0;
		if (gs_stagesurface_map(thumb_stage_[i], &data, &linesize)) {
			MotionEvent ev;
			ev.kind = MotionEvent::Kind::Frame;
			ev.seq = thumb_seq_[i];
			ev.ts = thumb_ts_[i];
			ev.thumb = image_from_bgra(data, thumb_w_, thumb_h_, linesize);
			ev.full_w = width_;
			ev.full_h = height_;
			gs_stagesurface_unmap(thumb_stage_[i]);
			post_motion(std::move(ev));
		}
		thumb_pending_[i] = false;
	}

	// Sample sparsely: often enough to measure motion, not every frame.
	const uint64_t every = moving_ ? kSampleEveryMoving : kSampleEveryStatic;
	if (!force && last_sample_seq_ && slot.seq - last_sample_seq_ < every)
		return;
	if (thumb_pending_[thumb_next_])
		return; // all stages busy (should not happen)

	gs_texture_t *tex = gs_texrender_get_texture(slot.texrender);
	if (!tex)
		return;
	gs_texrender_reset(thumb_tr_);
	if (!gs_texrender_begin(thumb_tr_, thumb_w_, thumb_h_))
		return;
	gs_ortho(0.0f, static_cast<float>(width_), 0.0f, static_cast<float>(height_), -100.0f, 100.0f);
	gs_blend_state_push();
	gs_blend_function(GS_BLEND_ONE, GS_BLEND_ZERO);
	gs_effect_t *effect = obs_get_base_effect(OBS_EFFECT_DEFAULT);
	gs_effect_set_texture(gs_effect_get_param_by_name(effect, "image"), tex);
	while (gs_effect_loop(effect, "Draw"))
		gs_draw_sprite(tex, 0, width_, height_);
	gs_blend_state_pop();
	gs_texrender_end(thumb_tr_);

	gs_stage_texture(thumb_stage_[thumb_next_], gs_texrender_get_texture(thumb_tr_));
	thumb_pending_[thumb_next_] = true;
	thumb_seq_[thumb_next_] = slot.seq;
	thumb_ts_[thumb_next_] = slot.ts;
	thumb_next_ = (thumb_next_ + 1) % kThumbStages;
	last_sample_seq_ = slot.seq;
}

bool PiiRedactFilter::capture(Slot &slot, uint32_t width, uint32_t height)
{
	gs_texrender_reset(slot.texrender);
	if (!gs_texrender_begin(slot.texrender, width, height))
		return false;

	struct vec4 clear_color;
	vec4_zero(&clear_color);
	gs_clear(GS_CLEAR_COLOR, &clear_color, 0.0f, 0);
	gs_ortho(0.0f, static_cast<float>(width), 0.0f, static_cast<float>(height), -100.0f, 100.0f);

	gs_blend_state_push();
	gs_blend_function(GS_BLEND_ONE, GS_BLEND_ZERO);
	if (obs_source_process_filter_begin(context_, GS_BGRA, OBS_ALLOW_DIRECT_RENDERING))
		obs_source_process_filter_end(context_, obs_get_base_effect(OBS_EFFECT_DEFAULT), width, height);
	gs_blend_state_pop();

	gs_texrender_end(slot.texrender);
	slot.valid = true;
	slot.seq = ++frame_seq_;
	slot.ts = os_gettime_ns();
	return true;
}

bool PiiRedactFilter::schedule_analysis(const Slot &slot, const RenderSettings &rs)
{
	if (!stage_)
		return false;

	// Map the frame staged on a previous render (mapping the frame we
	// just staged would stall the GPU pipeline).
	if (stage_pending_) {
		uint8_t *data = nullptr;
		uint32_t linesize = 0;
		if (gs_stagesurface_map(stage_, &data, &linesize)) {
			Job job;
			job.seq = stage_seq_;
			job.ts = stage_ts_;
			job.image = image_from_bgra(data, width_, height_, linesize);
			gs_stagesurface_unmap(stage_);
			{
				std::lock_guard<std::mutex> lock(job_mutex_);
				job_ = std::move(job);
				job_ready_ = true;
			}
			job_cv_.notify_one();
		} else {
			worker_busy_ = false;
		}
		stage_pending_ = false;
		return false;
	}

	// OCR always takes the newest frame once it is free, so it naturally
	// skips as many frames as a scan takes. A lost box forces a scan now.
	const uint64_t now = os_gettime_ns();
	if (worker_busy_ || (!force_scan_ && now - last_stage_ns_ < rs.interval_ns))
		return false;
	force_scan_ = false;

	gs_texture_t *tex = gs_texrender_get_texture(slot.texrender);
	if (!tex)
		return false;
	gs_stage_texture(stage_, tex);
	stage_pending_ = true;
	stage_seq_ = slot.seq;
	stage_ts_ = slot.ts;
	last_stage_ns_ = now;
	worker_busy_ = true;
	return true;
}

void PiiRedactFilter::draw_texture(gs_texture_t *tex, uint32_t width, uint32_t height)
{
	const bool previous = gs_framebuffer_srgb_enabled();
	gs_enable_framebuffer_srgb(true);

	gs_effect_t *effect = obs_get_base_effect(OBS_EFFECT_DEFAULT);
	gs_effect_set_texture_srgb(gs_effect_get_param_by_name(effect, "image"), tex);
	while (gs_effect_loop(effect, "Draw"))
		gs_draw_sprite(tex, 0, width, height);

	gs_enable_framebuffer_srgb(previous);
}

void PiiRedactFilter::draw_solid(const std::vector<Rect> &rects, uint32_t color)
{
	if (rects.empty())
		return;
	gs_effect_t *solid = obs_get_base_effect(OBS_EFFECT_SOLID);
	struct vec4 c;
	vec4_from_rgba(&c, color);
	gs_effect_set_vec4(gs_effect_get_param_by_name(solid, "color"), &c);
	while (gs_effect_loop(solid, "Solid")) {
		for (const Rect &r : rects) {
			gs_matrix_push();
			gs_matrix_translate3f(static_cast<float>(r.x), static_cast<float>(r.y), 0.0f);
			gs_draw_sprite(nullptr, 0, static_cast<uint32_t>(r.w), static_cast<uint32_t>(r.h));
			gs_matrix_pop();
		}
	}
}

void PiiRedactFilter::draw_filtered(gs_texture_t *tex, const std::vector<Rect> &rects, const RenderSettings &rs,
				    uint32_t width, uint32_t height)
{
	if (rects.empty())
		return;
	if (!redact_effect_) {
		// Never fail open: fall back to solid boxes.
		draw_solid(rects, 0xFF000000);
		return;
	}

	const bool previous = gs_framebuffer_srgb_enabled();
	gs_enable_framebuffer_srgb(true);

	struct vec2 texel;
	vec2_set(&texel, 1.0f / static_cast<float>(width), 1.0f / static_cast<float>(height));
	gs_effect_set_texture_srgb(gs_effect_get_param_by_name(redact_effect_, "image"), tex);
	gs_effect_set_vec2(gs_effect_get_param_by_name(redact_effect_, "texel_size"), &texel);
	gs_effect_set_float(gs_effect_get_param_by_name(redact_effect_, "block_size"), rs.strength);
	gs_effect_set_float(gs_effect_get_param_by_name(redact_effect_, "blur_radius"), rs.strength);

	const char *technique = rs.style == Style::Blur ? "Blur" : "Pixelate";
	while (gs_effect_loop(redact_effect_, technique)) {
		for (const Rect &r : rects) {
			gs_matrix_push();
			gs_matrix_translate3f(static_cast<float>(r.x), static_cast<float>(r.y), 0.0f);
			gs_draw_sprite_subregion(tex, 0, static_cast<uint32_t>(r.x), static_cast<uint32_t>(r.y),
						 static_cast<uint32_t>(r.w), static_cast<uint32_t>(r.h));
			gs_matrix_pop();
		}
	}

	gs_enable_framebuffer_srgb(previous);
}

void PiiRedactFilter::draw_outlines(const std::vector<Rect> &rects)
{
	std::vector<Rect> edges;
	const int t = 3;
	for (const Rect &r : rects) {
		edges.push_back({r.x, r.y, r.w, t});
		edges.push_back({r.x, r.bottom() - t, r.w, t});
		edges.push_back({r.x, r.y, t, r.h});
		edges.push_back({r.right() - t, r.y, t, r.h});
	}
	draw_solid(edges, 0xFF0000FF); // red (ABGR)
}

void PiiRedactFilter::render()
{
	obs_source_t *target = obs_filter_get_target(context_);
	obs_source_t *parent = obs_filter_get_parent(context_);
	if (!target || !parent) {
		obs_source_skip_video_filter(context_);
		return;
	}
	const uint32_t width = obs_source_get_base_width(target);
	const uint32_t height = obs_source_get_base_height(target);
	if (width == 0 || height == 0) {
		obs_source_skip_video_filter(context_);
		return;
	}

	RenderSettings rs;
	{
		std::lock_guard<std::mutex> lock(settings_mutex_);
		rs = render_settings_;
	}

	const size_t slots = static_cast<size_t>(rs.delay_frames) + 1;
	if (width != width_ || height != height_ || ring_.size() != slots) {
		reset_ring(width, height, slots);
		capture_pending_ = true;
	}

	// Capture once per video frame, even if we are rendered several times
	// (multiview, projectors, nested scenes).
	if (capture_pending_.exchange(false)) {
		Slot &slot = ring_[write_idx_];
		if (capture(slot, width, height)) {
			// The frame OCR scans is always sampled so its result can be
			// carried forward exactly.
			const bool staged = schedule_analysis(slot, rs);
			sample_motion(slot, staged);
			write_idx_ = (write_idx_ + 1) % ring_.size();
		}
	}

	const size_t newest = (write_idx_ + ring_.size() - 1) % ring_.size();
	const size_t out_idx = (newest + ring_.size() - static_cast<size_t>(rs.delay_frames)) % ring_.size();
	const Slot &out = ring_[out_idx];

	// Not enough history yet (start-up / resize) or panic: show nothing.
	const std::vector<Rect> full_frame = {Rect{0, 0, static_cast<int>(width), static_cast<int>(height)}};
	if (panic_ || !out.valid) {
		draw_solid(full_frame, 0xFF000000);
		return;
	}

	std::shared_ptr<const TrackerView> view;
	{
		std::lock_guard<std::mutex> lock(view_mutex_);
		view = view_;
	}
	std::vector<Rect> regions;
	bool verified = false;
	if (view) {
		for (const Rect &r : view->rects_for(out.seq, out.ts)) {
			const Rect c = r.clipped(static_cast<int>(width), static_cast<int>(height));
			if (!c.empty())
				regions.push_back(c);
		}
		verified = view->verified(out.seq);
	}

	if (rs.fail_safe && rs.delay_frames > 0 && !verified && !rs.debug) {
		draw_solid(full_frame, 0xFF000000);
		return;
	}

	gs_texture_t *tex = gs_texrender_get_texture(out.texrender);
	if (!tex) {
		draw_solid(full_frame, 0xFF000000);
		return;
	}

	draw_texture(tex, width, height);

	// Edge guard: while the page scrolls, the strip new content enters
	// through has not been read yet (and text there may be cut off). Cover
	// it until a scan has seen it.
	if (rs.edge_guard) {
		const double vy = scroll_vy_;
		if (std::fabs(vy) > 0.5) {
			const uint64_t scan_seq = scroll_seq_;
			const uint64_t since = out.seq > scan_seq ? out.seq - scan_seq : 0;
			const double travel = std::fabs(vy) * static_cast<double>(since + latency_frames_.load());
			const int strip = std::min(static_cast<int>(height),
						   static_cast<int>(std::ceil(travel)) + line_px_.load() * 3 / 2);
			if (vy < 0) // content moves up: new content enters at the bottom
				regions.push_back(
					{0, static_cast<int>(height) - strip, static_cast<int>(width), strip});
			else
				regions.push_back({0, 0, static_cast<int>(width), strip});
		}
	}

	if (rs.debug)
		draw_outlines(regions);
	else if (rs.style == Style::Box)
		draw_solid(regions, rs.color);
	else
		draw_filtered(tex, regions, rs, width, height);
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

bool style_modified(obs_properties_t *props, obs_property_t *, obs_data_t *settings)
{
	const Style style = static_cast<Style>(obs_data_get_int(settings, S_STYLE));
	obs_property_set_visible(obs_properties_get(props, S_COLOR), style == Style::Box);
	obs_property_set_visible(obs_properties_get(props, S_STRENGTH), style != Style::Box);
	return true;
}

bool backend_modified(obs_properties_t *props, obs_property_t *, obs_data_t *settings)
{
	const OcrBackend chosen = ocr_backend_from_id(obs_data_get_string(settings, S_BACKEND));
	const auto list = available_ocr_backends();
	const OcrBackend effective = chosen == OcrBackend::Auto && !list.empty() ? list.front() : chosen;
	obs_property_set_visible(obs_properties_get(props, S_TESSDATA), effective == OcrBackend::Tesseract);
	obs_property_set_visible(obs_properties_get(props, S_FAST), effective == OcrBackend::AppleVision);
	obs_property_set_visible(obs_properties_get(props, S_MINCONF), effective != OcrBackend::WindowsMediaOcr);
	return true;
}

obs_properties_t *PiiRedactFilter::properties()
{
	obs_properties_t *props = obs_properties_create();

	{
		std::string status;
		{
			std::lock_guard<std::mutex> lock(status_mutex_);
			status = status_;
		}
		obs_data_t *settings = obs_source_get_settings(context_);
		obs_data_set_string(settings, S_STATUS, status.c_str());
		obs_data_release(settings);
		obs_property_t *p =
			obs_properties_add_text(props, S_STATUS, obs_module_text("PIIRedact.Status"), OBS_TEXT_INFO);
		obs_property_text_set_info_type(p, status.rfind("OCR unavailable", 0) == 0 ? OBS_TEXT_INFO_ERROR
											   : OBS_TEXT_INFO_NORMAL);
	}

	obs_properties_t *detect = obs_properties_create();
	obs_properties_add_bool(detect, S_EMAIL, obs_module_text("PIIRedact.Email"));
	obs_properties_add_bool(detect, S_PHONE, obs_module_text("PIIRedact.Phone"));
	obs_properties_add_bool(detect, S_SSN, obs_module_text("PIIRedact.Ssn"));
	obs_properties_add_bool(detect, S_CARD, obs_module_text("PIIRedact.CreditCard"));
	obs_properties_add_bool(detect, S_ADDRESS, obs_module_text("PIIRedact.Address"));
	obs_properties_add_bool(detect, S_DOB, obs_module_text("PIIRedact.Dob"));
	obs_properties_add_bool(detect, S_SECRETS, obs_module_text("PIIRedact.Secrets"));
	obs_properties_add_bool(detect, S_IP, obs_module_text("PIIRedact.Ip"));
	obs_properties_add_text(detect, S_KEYWORDS, obs_module_text("PIIRedact.Keywords"), OBS_TEXT_MULTILINE);
	obs_properties_add_text(detect, S_REGEX, obs_module_text("PIIRedact.CustomRegex"), OBS_TEXT_MULTILINE);
	obs_properties_add_group(props, "group_detect", obs_module_text("PIIRedact.Group.Detect"), OBS_GROUP_NORMAL,
				 detect);

	obs_properties_t *style = obs_properties_create();
	obs_property_t *p = obs_properties_add_list(style, S_STYLE, obs_module_text("PIIRedact.Style"),
						    OBS_COMBO_TYPE_LIST, OBS_COMBO_FORMAT_INT);
	obs_property_list_add_int(p, obs_module_text("PIIRedact.Style.Box"), static_cast<long long>(Style::Box));
	obs_property_list_add_int(p, obs_module_text("PIIRedact.Style.Pixelate"),
				  static_cast<long long>(Style::Pixelate));
	obs_property_list_add_int(p, obs_module_text("PIIRedact.Style.Blur"), static_cast<long long>(Style::Blur));
	obs_property_set_modified_callback(p, style_modified);
	obs_properties_add_color(style, S_COLOR, obs_module_text("PIIRedact.Color"));
	obs_properties_add_float_slider(style, S_STRENGTH, obs_module_text("PIIRedact.Strength"), 4.0, 64.0, 1.0);
	obs_properties_add_int_slider(style, S_PADDING, obs_module_text("PIIRedact.Padding"), 0, 64, 1);
	obs_properties_add_int(style, S_PERSIST, obs_module_text("PIIRedact.Persist"), 0, 30000, 100);
	obs_properties_add_group(props, "group_style", obs_module_text("PIIRedact.Group.Style"), OBS_GROUP_NORMAL,
				 style);

	obs_properties_t *ocr = obs_properties_create();
	p = obs_properties_add_list(ocr, S_BACKEND, obs_module_text("PIIRedact.Backend"), OBS_COMBO_TYPE_LIST,
				    OBS_COMBO_FORMAT_STRING);
	obs_property_list_add_string(p, obs_module_text("PIIRedact.Backend.Auto"), ocr_backend_id(OcrBackend::Auto));
	for (OcrBackend b : available_ocr_backends()) {
		const char *label = b == OcrBackend::Tesseract         ? "PIIRedact.Backend.Tesseract"
				    : b == OcrBackend::WindowsMediaOcr ? "PIIRedact.Backend.Windows"
								       : "PIIRedact.Backend.Vision";
		obs_property_list_add_string(p, obs_module_text(label), ocr_backend_id(b));
	}
	obs_property_set_modified_callback(p, backend_modified);
	obs_properties_add_text(ocr, S_LANGUAGE, obs_module_text("PIIRedact.Language"), OBS_TEXT_DEFAULT);
	obs_properties_add_path(ocr, S_TESSDATA, obs_module_text("PIIRedact.Tessdata"), OBS_PATH_DIRECTORY, nullptr,
				nullptr);
	obs_properties_add_bool(ocr, S_FAST, obs_module_text("PIIRedact.FastMode"));
	obs_properties_add_int(ocr, S_THREADS, obs_module_text("PIIRedact.Threads"), 0, 32, 1);
	obs_properties_add_int(ocr, S_INTERVAL, obs_module_text("PIIRedact.Interval"), 0, 10000, 50);
	obs_properties_add_float_slider(ocr, S_SCALE, obs_module_text("PIIRedact.Scale"), 0.25, 3.0, 0.05);
	obs_properties_add_float_slider(ocr, S_MINCONF, obs_module_text("PIIRedact.MinConfidence"), 0.0, 100.0, 1.0);
	obs_properties_add_group(props, "group_ocr", obs_module_text("PIIRedact.Group.Ocr"), OBS_GROUP_NORMAL, ocr);

	obs_properties_t *safety = obs_properties_create();
	p = obs_properties_add_int(safety, S_DELAY, obs_module_text("PIIRedact.DelayFrames"), 0, kMaxDelayFrames, 1);
	obs_property_set_long_description(p, obs_module_text("PIIRedact.DelayFrames.Description"));
	obs_properties_add_bool(safety, S_EDGE, obs_module_text("PIIRedact.EdgeGuard"));
	obs_properties_add_bool(safety, S_FAILSAFE, obs_module_text("PIIRedact.FailSafe"));
	obs_properties_add_bool(safety, S_DEBUG, obs_module_text("PIIRedact.Debug"));
	obs_properties_add_group(props, "group_safety", obs_module_text("PIIRedact.Group.Safety"), OBS_GROUP_NORMAL,
				 safety);

	return props;
}

// ---------------------------------------------------------------------------
// C callbacks
// ---------------------------------------------------------------------------

const char *filter_get_name(void *)
{
	return obs_module_text("PIIRedact.Name");
}

void panic_hotkey(void *data, obs_hotkey_id, obs_hotkey_t *, bool pressed)
{
	if (pressed)
		static_cast<PiiRedactFilter *>(data)->toggle_panic();
}

void *filter_create(obs_data_t *settings, obs_source_t *source)
{
	auto *filter = new PiiRedactFilter(source);
	filter->update(settings);
	obs_hotkey_register_source(source, "PIIRedact.Panic", obs_module_text("PIIRedact.Hotkey.Panic"), panic_hotkey,
				   filter);
	return filter;
}

void filter_destroy(void *data)
{
	delete static_cast<PiiRedactFilter *>(data);
}

void filter_update(void *data, obs_data_t *settings)
{
	static_cast<PiiRedactFilter *>(data)->update(settings);
}

void filter_tick(void *data, float)
{
	static_cast<PiiRedactFilter *>(data)->tick();
}

void filter_render(void *data, gs_effect_t *)
{
	static_cast<PiiRedactFilter *>(data)->render();
}

obs_properties_t *filter_properties(void *data)
{
	return static_cast<PiiRedactFilter *>(data)->properties();
}

void filter_defaults(obs_data_t *settings)
{
	obs_data_set_default_bool(settings, S_EMAIL, true);
	obs_data_set_default_bool(settings, S_PHONE, true);
	obs_data_set_default_bool(settings, S_SSN, true);
	obs_data_set_default_bool(settings, S_CARD, true);
	obs_data_set_default_bool(settings, S_IP, false);
	obs_data_set_default_bool(settings, S_ADDRESS, true);
	obs_data_set_default_bool(settings, S_DOB, true);
	obs_data_set_default_bool(settings, S_SECRETS, true);
	obs_data_set_default_string(settings, S_KEYWORDS, "");
	obs_data_set_default_string(settings, S_REGEX, "");
	obs_data_set_default_int(settings, S_STYLE, static_cast<long long>(Style::Box));
	obs_data_set_default_int(settings, S_COLOR, 0xFF000000);
	obs_data_set_default_double(settings, S_STRENGTH, 16.0);
	obs_data_set_default_int(settings, S_PADDING, 6);
	obs_data_set_default_int(settings, S_PERSIST, 1500);
	obs_data_set_default_string(settings, S_BACKEND, "auto");
	obs_data_set_default_string(settings, S_LANGUAGE, "");
	obs_data_set_default_string(settings, S_TESSDATA, "");
	obs_data_set_default_bool(settings, S_FAST, false);
	obs_data_set_default_int(settings, S_INTERVAL, 0);
	obs_data_set_default_int(settings, S_THREADS, 0);
	obs_data_set_default_double(settings, S_SCALE, 1.0);
	obs_data_set_default_double(settings, S_MINCONF, 0.0);
	obs_data_set_default_int(settings, S_DELAY, 0);
	obs_data_set_default_bool(settings, S_FAILSAFE, false);
	obs_data_set_default_bool(settings, S_DEBUG, false);
	obs_data_set_default_bool(settings, S_EDGE, true);
}

} // namespace

extern "C" void register_pii_redact_filter(void)
{
	struct obs_source_info info = {};
	info.id = "pii_redact_filter";
	info.type = OBS_SOURCE_TYPE_FILTER;
	info.output_flags = OBS_SOURCE_VIDEO;
	info.get_name = filter_get_name;
	info.create = filter_create;
	info.destroy = filter_destroy;
	info.update = filter_update;
	info.video_tick = filter_tick;
	info.video_render = filter_render;
	info.get_properties = filter_properties;
	info.get_defaults = filter_defaults;
	obs_register_source(&info);
}
