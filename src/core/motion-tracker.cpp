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

#include "motion-tracker.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <utility>

namespace pii {

namespace {

// Mean absolute difference between patch p in a and p shifted by (dx, dy) in
// b. Pixels whose shifted position falls outside b are skipped; if fewer
// than half remain the result is +inf.
double patch_sad(const Image &a, const Image &b, const Rect &p, int dx, int dy)
{
	const int bw = static_cast<int>(b.width);
	const int bh = static_cast<int>(b.height);
	const int x0 = std::max(p.x, -dx);
	const int x1 = std::min(p.right(), bw - dx);
	const int y0 = std::max(p.y, -dy);
	const int y1 = std::min(p.bottom(), bh - dy);
	if (x1 <= x0 || y1 <= y0)
		return std::numeric_limits<double>::infinity();
	const long long valid = static_cast<long long>(x1 - x0) * (y1 - y0);
	if (valid * 2 < static_cast<long long>(p.w) * p.h)
		return std::numeric_limits<double>::infinity();

	uint64_t sum = 0;
	for (int y = y0; y < y1; y++) {
		const uint8_t *ra = a.pixels.data() + static_cast<size_t>(y) * a.width;
		const uint8_t *rb = b.pixels.data() + static_cast<size_t>(y + dy) * b.width + dx;
		for (int x = x0; x < x1; x++)
			sum += static_cast<uint64_t>(std::abs(static_cast<int>(ra[x]) - static_cast<int>(rb[x])));
	}
	return static_cast<double>(sum) / static_cast<double>(valid);
}

} // namespace

// Exhaustive search of offsets within +-radius of (cx, cy); returns the
// best offset and its SAD. Small radii only (called per pyramid level).
static void search_window(const Image &a, const Image &b, const Rect &patch, int cx, int cy, int radius, int pred_dx,
			  int pred_dy, int &bx, int &by, double &best_sad)
{
	double best_cost = std::numeric_limits<double>::infinity();
	best_sad = std::numeric_limits<double>::infinity();
	bx = cx;
	by = cy;
	for (int oy = -radius; oy <= radius; oy++) {
		for (int ox = -radius; ox <= radius; ox++) {
			const int x = cx + ox, y = cy + oy;
			const double sad = patch_sad(a, b, patch, x, y);
			// Tiny bias towards the prediction so flat areas don't wander.
			const double c = sad + 0.02 * (std::abs(x - pred_dx) + std::abs(y - pred_dy));
			if (c < best_cost) {
				best_cost = c;
				best_sad = sad;
				bx = x;
				by = y;
			}
		}
	}
}

// 1-D search along one axis using projections: each row (or column) of the
// patch is summed into one value, so a +-64 px search costs only a few
// thousand operations. `other` is the current offset on the other axis.
static int profile_search(const Image &a, const Image &b, const Rect &p, bool vertical, int center, int other,
			  int radius)
{
	const int n = vertical ? p.h : p.w; // profile length
	std::vector<double> pa(static_cast<size_t>(n), 0.0);
	for (int y = 0; y < p.h; y++) {
		const uint8_t *row = a.pixels.data() + static_cast<size_t>(p.y + y) * a.width;
		for (int x = 0; x < p.w; x++)
			pa[static_cast<size_t>(vertical ? y : x)] += row[p.x + x];
	}
	const int len_other = vertical ? p.w : p.h;
	for (double &v : pa)
		v /= len_other;

	const int bw = static_cast<int>(b.width), bh = static_cast<int>(b.height);
	int best = center;
	double best_cost = std::numeric_limits<double>::infinity();
	std::vector<double> pb(static_cast<size_t>(n));
	for (int off = center - radius; off <= center + radius; off++) {
		const int dx = vertical ? other : off;
		const int dy = vertical ? off : other;
		// The other axis must stay inside b; along the search axis we skip
		// entries that fall outside.
		const int ox0 = std::max(p.x + dx, 0), ox1 = std::min(p.right() + dx, bw);
		const int oy0 = std::max(p.y + dy, 0), oy1 = std::min(p.bottom() + dy, bh);
		if (ox1 <= ox0 || oy1 <= oy0)
			continue;
		double sum = 0.0;
		int valid = 0;
		for (int i = 0; i < n; i++) {
			double acc = 0.0;
			int cnt = 0;
			if (vertical) {
				const int y = p.y + i + dy;
				if (y < 0 || y >= bh)
					continue;
				const uint8_t *row = b.pixels.data() + static_cast<size_t>(y) * b.width;
				for (int x = ox0; x < ox1; x++, cnt++)
					acc += row[x];
			} else {
				const int x = p.x + i + dx;
				if (x < 0 || x >= bw)
					continue;
				for (int y = oy0; y < oy1; y++, cnt++)
					acc += b.pixels[static_cast<size_t>(y) * b.width + x];
			}
			if (!cnt)
				continue;
			sum += std::fabs(acc / cnt - pa[static_cast<size_t>(i)]);
			valid++;
		}
		if (valid * 2 < n)
			continue;
		const double cost = sum / valid + 0.02 * std::abs(off - center);
		if (cost < best_cost) {
			best_cost = cost;
			best = off;
		}
	}
	return best;
}

// Large motions: alternate vertical / horizontal projection searches, then
// refine the 2-D offset exhaustively in a small window.
static void pyramid_search(const Image &a, const Image &b, const Rect &patch, int pred_dx, int pred_dy, int radius,
			   int &dx, int &dy, double &sad)
{
	constexpr int kDirect = 4;
	if (radius <= kDirect) {
		search_window(a, b, patch, pred_dx, pred_dy, radius, pred_dx, pred_dy, dx, dy, sad);
		return;
	}
	int cx = pred_dx, cy = pred_dy;
	for (int iter = 0; iter < 2; iter++) {
		cy = profile_search(a, b, patch, true, iter ? cy : pred_dy, cx, iter ? 3 : radius);
		cx = profile_search(a, b, patch, false, iter ? cx : pred_dx, cy, iter ? 3 : radius);
	}
	search_window(a, b, patch, cx, cy, 2, pred_dx, pred_dy, dx, dy, sad);
	// Fall back to a direct search near the prediction if that did better
	// (protects against a wrong projection match).
	int fx = 0, fy = 0;
	double fsad = 0;
	search_window(a, b, patch, pred_dx, pred_dy, kDirect, pred_dx, pred_dy, fx, fy, fsad);
	if (fsad < sad) {
		dx = fx;
		dy = fy;
		sad = fsad;
	}
}

void match_patch(const Image &a, const Image &b, const Rect &patch_in, int pred_dx, int pred_dy, int radius, int &dx,
		 int &dy, double &error)
{
	dx = pred_dx;
	dy = pred_dy;
	error = -1.0;
	const Rect patch = patch_in.clipped(static_cast<int>(a.width), static_cast<int>(a.height));
	if (patch.empty() || a.channels != 1 || b.channels != 1 || a.width != b.width || a.height != b.height)
		return;

	// Cheap exits for the common cases: static screen, constant scroll.
	constexpr double kGood = 1.5;
	const double at_pred = patch_sad(a, b, patch, pred_dx, pred_dy);
	if (at_pred < kGood) {
		error = at_pred;
		return;
	}
	if (pred_dx != 0 || pred_dy != 0) {
		const double at_zero = patch_sad(a, b, patch, 0, 0);
		if (at_zero < kGood) {
			dx = dy = 0;
			error = at_zero;
			return;
		}
	}

	int bx = pred_dx, by = pred_dy;
	double best = 0;
	pyramid_search(a, b, patch, pred_dx, pred_dy, radius, bx, by, best);
	if (std::isinf(best))
		return; // patch left the frame: keep the prediction
	dx = bx;
	dy = by;
	error = best;
}

std::vector<Rect> TrackerView::rects_for(uint64_t seq, uint64_t ts) const
{
	std::vector<Rect> out;
	for (const TrackState &t : tracks) {
		if (t.dead && ts > t.dead_ts + persist_ns)
			continue;
		auto it = t.positions.upper_bound(seq);
		if (it == t.positions.begin())
			continue; // the text did not exist yet in that frame
		--it;
		Rect r = it->second;
		const uint64_t k = seq - it->first;
		if (k > 0) {
			// Extrapolate and grow along the motion to absorb the guess.
			const double ex = t.vx * static_cast<double>(k);
			const double ey = t.vy * static_cast<double>(k);
			r.x += static_cast<int>(std::lround(ex));
			r.y += static_cast<int>(std::lround(ey));
			const int gx = static_cast<int>(std::ceil(std::fabs(t.vx) * static_cast<double>(k + 1)));
			const int gy = static_cast<int>(std::ceil(std::fabs(t.vy) * static_cast<double>(k + 1)));
			r = {r.x - gx, r.y - gy, r.w + 2 * gx, r.h + 2 * gy};
		}
		out.push_back(r);
	}
	return merge_rects(std::move(out));
}

MotionTracker::MotionTracker(const MotionConfig &config) : config_(config) {}

void MotionTracker::clear()
{
	frames_.clear();
	tracks_.clear();
	pending_scans_.clear();
	newest_scan_seq_ = prev_scan_seq_ = 0;
	any_scan_ = false;
	rescan_requested_ = false;
}

bool MotionTracker::take_rescan_request()
{
	const bool r = rescan_requested_;
	rescan_requested_ = false;
	return r;
}

const MotionTracker::Frame *MotionTracker::frame_at(uint64_t seq) const
{
	if (frames_.empty() || seq < frames_.front().seq || seq > frames_.back().seq)
		return nullptr;
	// Frames are consecutive except for the odd dropped one; try direct index.
	const size_t idx = static_cast<size_t>(seq - frames_.front().seq);
	if (idx < frames_.size() && frames_[idx].seq == seq)
		return &frames_[idx];
	auto it = std::lower_bound(frames_.begin(), frames_.end(), seq,
				   [](const Frame &f, uint64_t s) { return f.seq < s; });
	return it != frames_.end() && it->seq == seq ? &*it : nullptr;
}

Rect MotionTracker::to_thumb(const Rect &r) const
{
	return r.scaled(sx_, sy_);
}

bool MotionTracker::step(Track &t, const Frame &from, const Frame &to, bool forward)
{
	auto it = t.st.positions.find(from.seq);
	if (it == t.st.positions.end())
		return true;
	const Rect cur = it->second;

	// Frames are sampled sparsely; `gap` is how many video frames apart
	// these two samples are. Velocity is kept per video frame.
	const double gap = static_cast<double>(forward ? to.seq - from.seq : from.seq - to.seq);
	const double dir = forward ? gap : -gap;
	const int pdx = static_cast<int>(std::lround(dir * t.st.vx * sx_));
	const int pdy = static_cast<int>(std::lround(dir * t.st.vy * sy_));
	const int radius =
		std::min(config_.search_radius * static_cast<int>(std::max(1.0, gap)), config_.max_search_radius);

	const Rect patch = to_thumb(cur).padded(config_.context);
	int dx = 0, dy = 0;
	double err = 0.0;
	match_patch(from.grey, to.grey, patch, pdx, pdy, radius, dx, dy, err);

	bool ok = true;
	if (err > config_.lost_threshold) {
		// Content under the box changed; do not guess, keep the box put.
		dx = dy = 0;
		ok = false;
	}

	const double fdx = dx / sx_;
	const double fdy = dy / sy_;
	Rect next = cur;
	next.x += static_cast<int>(std::lround(fdx));
	next.y += static_cast<int>(std::lround(fdy));
	t.st.positions[to.seq] = next;
	if (forward && ok && gap > 0) {
		t.st.vx = fdx / gap;
		t.st.vy = fdy / gap;
	}
	return ok;
}

void MotionTracker::propagate_forward(Track &t, uint64_t from_seq)
{
	for (const Frame &f : frames_) {
		if (f.seq <= from_seq)
			continue;
		auto prev = t.st.positions.upper_bound(f.seq - 1);
		if (prev == t.st.positions.begin())
			continue;
		--prev;
		const Frame *src = frame_at(prev->first);
		if (!src) {
			t.st.positions[f.seq] = prev->second;
			continue;
		}
		if (!step(t, *src, f, true))
			rescan_requested_ = true;
	}
}

void MotionTracker::propagate_backward(Track &t, uint64_t from_seq, uint64_t to_seq)
{
	// Walk the sampled frames from `from_seq` back to `to_seq`.
	const Frame *cur = frame_at(from_seq);
	if (!cur)
		return;
	for (auto it = frames_.rbegin(); it != frames_.rend(); ++it) {
		if (it->seq >= cur->seq)
			continue;
		if (it->seq < to_seq)
			break;
		step(t, *cur, *it, false);
		cur = &*it;
	}
}

void MotionTracker::add_frame(uint64_t seq, uint64_t ts, Image grey, uint32_t full_w, uint32_t full_h)
{
	if (grey.empty() || grey.channels != 1 || full_w == 0 || full_h == 0)
		return;
	const double sx = static_cast<double>(grey.width) / full_w;
	const double sy = static_cast<double>(grey.height) / full_h;
	if (full_w != full_w_ || full_h != full_h_ ||
	    (!frames_.empty() &&
	     (frames_.back().grey.width != grey.width || frames_.back().grey.height != grey.height))) {
		clear();
		full_w_ = full_w;
		full_h_ = full_h;
	}
	sx_ = sx;
	sy_ = sy;
	if (!frames_.empty() && seq <= frames_.back().seq)
		return; // out of order, ignore

	frames_.push_back({seq, ts, std::move(grey)});
	const Frame &f = frames_.back();
	const Frame *prev = frames_.size() > 1 ? &frames_[frames_.size() - 2] : nullptr;

	for (Track &t : tracks_) {
		if (t.st.positions.empty())
			continue;
		auto last = t.st.positions.rbegin();
		if (last->first >= seq)
			continue;
		if (prev && last->first == prev->seq) {
			if (!step(t, *prev, f, true))
				rescan_requested_ = true;
		} else {
			t.st.positions[seq] = last->second;
		}
	}

	// Scans that were waiting for this frame.
	if (!pending_scans_.empty()) {
		std::vector<Scan> ready;
		std::vector<Scan> waiting;
		for (Scan &s : pending_scans_)
			(s.seq <= seq ? ready : waiting).push_back(std::move(s));
		pending_scans_ = std::move(waiting);
		for (Scan &s : ready)
			apply_scan(std::move(s));
	}

	prune();
}

void MotionTracker::add_scan(uint64_t seq, std::vector<Rect> rects)
{
	if (frames_.empty() || seq > frames_.back().seq) {
		pending_scans_.push_back({seq, std::move(rects)});
		return;
	}
	apply_scan({seq, std::move(rects)});
}

void MotionTracker::apply_scan(Scan scan)
{
	// If OCR took longer than the history, anchor to the oldest frame we have.
	uint64_t seq = scan.seq;
	if (!frames_.empty() && seq < frames_.front().seq)
		seq = frames_.front().seq;
	const Frame *frame = frame_at(seq);
	const uint64_t scan_ts = frame ? frame->ts : (frames_.empty() ? 0 : frames_.back().ts);

	if (any_scan_ && scan.seq <= newest_scan_seq_)
		return; // stale (older than a scan already applied)
	prev_scan_seq_ = any_scan_ ? newest_scan_seq_ : (frames_.empty() ? seq : frames_.front().seq);
	newest_scan_seq_ = scan.seq;
	any_scan_ = true;

	std::vector<Rect> dets = merge_rects(std::move(scan.rects));
	std::vector<bool> matched_track(tracks_.size(), false);

	for (const Rect &d : dets) {
		// Associate with the track whose box (at this frame) overlaps most.
		int best = -1;
		double best_score = 0.0;
		for (size_t i = 0; i < tracks_.size(); i++) {
			const auto &pos = tracks_[i].st.positions;
			auto it = pos.upper_bound(seq);
			if (it == pos.begin())
				continue;
			--it;
			const Rect &p = it->second;
			double score = iou(p, d);
			if (score == 0.0 && p.intersects(d))
				score = 0.01;
			if (score > best_score) {
				best_score = score;
				best = static_cast<int>(i);
			}
		}

		if (best >= 0) {
			Track &t = tracks_[static_cast<size_t>(best)];
			matched_track[static_cast<size_t>(best)] = true;
			t.misses = 0;
			t.st.dead = false;
			// Re-anchor to the exact OCR rect and redo the forward path.
			for (auto it = t.st.positions.upper_bound(seq); it != t.st.positions.end();)
				it = t.st.positions.erase(it);
			t.st.positions[seq] = d;
			propagate_forward(t, seq);
		} else {
			Track t;
			t.st.positions[seq] = d;
			uint64_t back_to = prev_scan_seq_;
			const uint64_t newest = frames_.empty() ? seq : frames_.back().seq;
			if (config_.lookback_frames && newest > config_.lookback_frames)
				back_to = std::min(back_to, newest - config_.lookback_frames);
			else if (config_.lookback_frames)
				back_to = 0;
			propagate_backward(t, seq, back_to);
			propagate_forward(t, seq);
			tracks_.push_back(std::move(t));
			matched_track.push_back(true);
		}
	}

	// Tracks this scan should have seen but did not.
	for (size_t i = 0; i < matched_track.size() && i < tracks_.size(); i++) {
		if (matched_track[i])
			continue;
		Track &t = tracks_[i];
		if (t.st.positions.empty() || t.st.positions.begin()->first > seq)
			continue;
		t.misses++;
		if (t.misses > config_.tolerated_misses && !t.st.dead) {
			t.st.dead = true;
			t.st.dead_ts = scan_ts;
		}
	}
}

void MotionTracker::prune()
{
	// A dead track is dropped once even the oldest frame we keep (and could
	// still output with a delay) is past its persistence window.
	const uint64_t oldest_ts = frames_.empty() ? 0 : frames_.front().ts;
	tracks_.erase(std::remove_if(tracks_.begin(), tracks_.end(),
				     [&](const Track &t) {
					     return t.st.positions.empty() ||
						    (t.st.dead && oldest_ts > t.st.dead_ts + config_.persist_ns);
				     }),
		      tracks_.end());

	while (frames_.size() > config_.history_frames)
		frames_.pop_front();
	if (frames_.empty())
		return;
	const uint64_t oldest = frames_.front().seq;
	for (Track &t : tracks_) {
		auto &pos = t.st.positions;
		// Keep the last entry before `oldest` for floor lookups.
		auto it = pos.lower_bound(oldest);
		if (it != pos.begin()) {
			--it;
			pos.erase(pos.begin(), it);
		}
	}
	// Bound pending scans in case thumbnails stop arriving.
	if (pending_scans_.size() > 8)
		pending_scans_.erase(pending_scans_.begin(), pending_scans_.end() - 8);
}

double MotionTracker::max_speed() const
{
	double m = 0.0;
	for (const Track &t : tracks_)
		if (!t.st.dead)
			m = std::max(m, std::hypot(t.st.vx, t.st.vy));
	return m;
}

TrackerView MotionTracker::view(uint64_t from_seq) const
{
	TrackerView v;
	v.newest_scan_seq = newest_scan_seq_;
	v.any_scan = any_scan_;
	v.persist_ns = config_.persist_ns;
	v.tracks.reserve(tracks_.size());
	for (const Track &t : tracks_) {
		TrackState s;
		s.vx = t.st.vx;
		s.vy = t.st.vy;
		s.dead = t.st.dead;
		s.dead_ts = t.st.dead_ts;
		auto it = t.st.positions.lower_bound(from_seq);
		if (it != t.st.positions.begin())
			--it;
		s.positions.insert(it, t.st.positions.end());
		v.tracks.push_back(std::move(s));
	}
	return v;
}

} // namespace pii
