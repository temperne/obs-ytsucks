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
//   OCR (Tesseract / Windows.Media.Ocr / Apple Vision) -> PiiMatcher ->
//   RegionTracker.

#include "pii-redact-filter.h"

#include "core/image.hpp"
#include "core/pii-matcher.hpp"
#include "core/region-tracker.hpp"
#include "ocr/ocr-engine.hpp"

#include <obs-module.h>
#include <graphics/vec2.h>
#include <graphics/vec4.h>
#include <util/platform.h>
#include <plugin-support.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
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
constexpr const char *S_MINCONF = "min_confidence";
constexpr const char *S_DELAY = "delay_frames";
constexpr const char *S_FAILSAFE = "fail_safe";
constexpr const char *S_DEBUG = "debug_outlines";
constexpr const char *S_STATUS = "status";

constexpr int kMaxDelayFrames = 120;

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
	uint64_t interval_ns = 250000000ULL;
};

// Settings the analysis thread needs.
struct AnalysisSettings {
	MatcherConfig matcher;
	OcrConfig ocr;
	double scale = 1.0;
	int padding = 6;
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
	void schedule_analysis(const Slot &slot, const RenderSettings &rs);
	void draw_texture(gs_texture_t *tex, uint32_t width, uint32_t height);
	void draw_solid(const std::vector<Rect> &rects, uint32_t color);
	void draw_filtered(gs_texture_t *tex, const std::vector<Rect> &rects, const RenderSettings &rs, uint32_t width,
			   uint32_t height);
	void draw_outlines(const std::vector<Rect> &rects);

	// analysis thread
	void worker_main();

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

	std::mutex tracker_mutex_;
	RegionTracker tracker_;

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

	const uint64_t persist_ns =
		static_cast<uint64_t>(std::max<long long>(0, obs_data_get_int(settings, S_PERSIST))) * 1000000ULL;

	{
		std::lock_guard<std::mutex> lock(settings_mutex_);
		render_settings_ = rs;
		analysis_settings_ = std::move(as);
		analysis_generation_++;
	}
	{
		std::lock_guard<std::mutex> lock(tracker_mutex_);
		tracker_.set_persistence_ns(persist_ns);
	}
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
	std::unique_ptr<OcrEngine> engine;
	std::unique_ptr<PiiMatcher> matcher;
	uint64_t generation = UINT64_MAX;
	AnalysisSettings as;
	std::string engine_error;
	// Rebuilding the OCR engine is expensive; only do it when its config changed.
	std::string engine_key;

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

			const std::string key = std::string(ocr_backend_id(as.ocr.backend)) + "|" + as.ocr.language +
						"|" + as.ocr.tessdata_path + "|" + (as.ocr.fast_mode ? "1" : "0");
			if (key != engine_key) {
				engine_key = key;
				engine.reset();
				engine_error.clear();
				engine = create_ocr_engine(as.ocr, engine_error);
				if (engine)
					obs_log(LOG_INFO, "OCR engine: %s", engine->name());
				else
					obs_log(LOG_ERROR, "OCR engine unavailable: %s", engine_error.c_str());
			}
		}

		if (!engine) {
			set_status("OCR unavailable: " + engine_error);
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

		std::vector<OcrLine> lines = engine->recognize(img);
		std::vector<Detection> detections = matcher->match(lines);

		std::vector<Rect> rects;
		rects.reserve(detections.size());
		for (const Detection &d : detections) {
			Rect r = d.box.scaled(back_x, back_y)
					 .padded(as.padding)
					 .clipped(static_cast<int>(src_w), static_cast<int>(src_h));
			if (!r.empty())
				rects.push_back(r);
		}

		{
			std::lock_guard<std::mutex> lock(tracker_mutex_);
			tracker_.add_result(job.seq, job.ts, std::move(rects));
		}

		const auto ms =
			std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
				.count();
		size_t words = 0;
		for (const OcrLine &l : lines)
			words += l.words.size();
		char buf[256];
		snprintf(buf, sizeof(buf), "%s: last scan %lld ms, %zu words, %zu redactions (%ux%u @ %.2fx)",
			 engine->name(), static_cast<long long>(ms), words, detections.size(), src_w, src_h, as.scale);
		set_status(buf);

		worker_busy_ = false;
	}

	engine.reset();
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

	std::lock_guard<std::mutex> lock(tracker_mutex_);
	tracker_.clear();
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

void PiiRedactFilter::schedule_analysis(const Slot &slot, const RenderSettings &rs)
{
	if (!stage_)
		return;

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
		return;
	}

	const uint64_t now = os_gettime_ns();
	if (worker_busy_ || now - last_stage_ns_ < rs.interval_ns)
		return;

	gs_texture_t *tex = gs_texrender_get_texture(slot.texrender);
	if (!tex)
		return;
	gs_stage_texture(stage_, tex);
	stage_pending_ = true;
	stage_seq_ = slot.seq;
	stage_ts_ = slot.ts;
	last_stage_ns_ = now;
	worker_busy_ = true;
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
			schedule_analysis(slot, rs);
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

	std::vector<Rect> regions;
	bool verified = true;
	{
		std::lock_guard<std::mutex> lock(tracker_mutex_);
		regions = tracker_.regions_for(out.ts);
		verified = tracker_.verified(out.seq);
		tracker_.prune(out.ts);
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
	obs_properties_add_int(ocr, S_INTERVAL, obs_module_text("PIIRedact.Interval"), 0, 10000, 50);
	obs_properties_add_float_slider(ocr, S_SCALE, obs_module_text("PIIRedact.Scale"), 0.25, 3.0, 0.05);
	obs_properties_add_float_slider(ocr, S_MINCONF, obs_module_text("PIIRedact.MinConfidence"), 0.0, 100.0, 1.0);
	obs_properties_add_group(props, "group_ocr", obs_module_text("PIIRedact.Group.Ocr"), OBS_GROUP_NORMAL, ocr);

	obs_properties_t *safety = obs_properties_create();
	p = obs_properties_add_int(safety, S_DELAY, obs_module_text("PIIRedact.DelayFrames"), 0, kMaxDelayFrames, 1);
	obs_property_set_long_description(p, obs_module_text("PIIRedact.DelayFrames.Description"));
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
	obs_data_set_default_int(settings, S_INTERVAL, 200);
	obs_data_set_default_double(settings, S_SCALE, 1.0);
	obs_data_set_default_double(settings, S_MINCONF, 0.0);
	obs_data_set_default_int(settings, S_DELAY, 0);
	obs_data_set_default_bool(settings, S_FAILSAFE, false);
	obs_data_set_default_bool(settings, S_DEBUG, false);
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
