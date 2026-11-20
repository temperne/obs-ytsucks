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

#include "bands.hpp"

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
	have_verified_ = false;
	verified_img_ = Image();
	unverified_.clear();
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

namespace {

constexpr int kStrips = 8;

// Mean of each row of `img` between columns [x0, x1).
std::vector<double> row_profile(const Image &img, int x0, int x1)
{
	std::vector<double> p(img.height);
	for (uint32_t y = 0; y < img.height; y++) {
		const uint8_t *row = img.pixels.data() + static_cast<size_t>(y) * img.width;
		uint32_t sum = 0;
		for (int x = x0; x < x1; x++)
			sum += row[x];
		p[y] = static_cast<double>(sum) / std::max(1, x1 - x0);
	}
	return p;
}

// Mean of the smallest `keep` fraction of `v` (robust to rows that do not
// follow the motion, e.g. a fixed toolbar or taskbar inside a scrolling strip).
double trimmed_mean(std::vector<double> &v, double keep)
{
	if (v.empty())
		return std::numeric_limits<double>::infinity();
	const size_t n = std::max<size_t>(1, static_cast<size_t>(static_cast<double>(v.size()) * keep));
	std::nth_element(v.begin(), v.begin() + static_cast<std::ptrdiff_t>(n - 1), v.end());
	double sum = 0;
	for (size_t i = 0; i < n; i++)
		sum += v[i];
	return sum / static_cast<double>(n);
}

// Mean abs difference of columns [x0, x1) between cur(y) and prev(y - s),
// sampled every 2nd pixel. +inf if fewer than half the rows overlap.
double strip_mad(const Image &prev, const Image &cur, int x0, int x1, int s)
{
	const int h = static_cast<int>(cur.height);
	std::vector<double> rows;
	for (int y = std::max(0, s); y < std::min(h, h + s); y += 2) {
		const uint8_t *rc = cur.pixels.data() + static_cast<size_t>(y) * cur.width;
		const uint8_t *rp = prev.pixels.data() + static_cast<size_t>(y - s) * prev.width;
		uint64_t sum = 0, n = 0;
		for (int x = x0; x < x1; x += 2) {
			sum += static_cast<uint64_t>(std::abs(static_cast<int>(rc[x]) - static_cast<int>(rp[x])));
			n++;
		}
		if (n)
			rows.push_back(static_cast<double>(sum) / static_cast<double>(n));
	}
	if (static_cast<int>(rows.size()) * 4 < h)
		return std::numeric_limits<double>::infinity();
	return trimmed_mean(rows, 0.7);
}

} // namespace

void MotionTracker::measure_strips(const Frame &prev, Frame &cur)
{
	const int W = static_cast<int>(cur.grey.width);
	const int H = static_cast<int>(cur.grey.height);
	cur.shift.assign(kStrips, 0);
	cur.ok.assign(kStrips, 1);
	if (strip_vy_.size() != kStrips)
		strip_vy_.assign(kStrips, 0.0);
	const double gap = static_cast<double>(cur.seq - prev.seq);
	constexpr double kGood = 3.0;

	for (int k = 0; k < kStrips; k++) {
		const int x0 = k * W / kStrips;
		const int x1 = (k + 1) * W / kStrips;
		const std::vector<double> pa = row_profile(prev.grey, x0, x1);
		const std::vector<double> pb = row_profile(cur.grey, x0, x1);

		// Blank strip: nothing to track.
		double mean = 0;
		for (double v : pb)
			mean += v;
		mean /= std::max(1, H);
		double dev = 0;
		for (double v : pb)
			dev += std::fabs(v - mean);
		if (dev / std::max(1, H) < 0.5) {
			strip_vy_[k] *= 0.5;
			continue;
		}

		const int pred = static_cast<int>(std::lround(strip_vy_[k] * gap * sy_));
		// Scroll-wheel jumps can move content 50+ px per frame, so search
		// (almost) the whole range; the 1-D profile match makes this cheap.
		const int radius = H / 2 + std::abs(pred);

		std::vector<double> diffs;
		auto profile_cost = [&](int sh) {
			diffs.clear();
			for (int y = std::max(0, sh); y < std::min(H, H + sh); y++)
				diffs.push_back(
					std::fabs(pb[static_cast<size_t>(y)] - pa[static_cast<size_t>(y - sh)]));
			if (static_cast<int>(diffs.size()) * 2 < H)
				return std::numeric_limits<double>::infinity();
			return trimmed_mean(diffs, 0.7);
		};
		// Pass 1: plain mean over all shifts (cheap); pass 2: robust trimmed
		// score only for the best few candidates (+ zero and the prediction).
		std::vector<std::pair<double, int>> coarse;
		for (int sh = pred - radius; sh <= pred + radius; sh++) {
			double sum = 0;
			int n = 0;
			for (int y = std::max(0, sh); y < std::min(H, H + sh); y += 2) {
				sum += std::fabs(pb[static_cast<size_t>(y)] - pa[static_cast<size_t>(y - sh)]);
				n++;
			}
			if (n * 4 >= H)
				coarse.emplace_back(sum / n, sh);
		}
		const size_t keep = std::min<size_t>(6, coarse.size());
		std::partial_sort(coarse.begin(), coarse.begin() + static_cast<std::ptrdiff_t>(keep), coarse.end());
		std::vector<int> cand_shifts = {0, pred};
		for (size_t i = 0; i < keep; i++)
			cand_shifts.push_back(coarse[i].second);

		int best = 0;
		double best_cost = profile_cost(0);
		for (int sh : cand_shifts) {
			const double c = profile_cost(sh) + 0.002 * std::abs(sh - pred);
			if (c < best_cost) {
				best_cost = c;
				best = sh;
			}
		}

		// Confirm in 2-D; fall back to "not moving" or "unknown".
		const double mad_best = strip_mad(prev.grey, cur.grey, x0, x1, best);
		const double mad_zero = best == 0 ? mad_best : strip_mad(prev.grey, cur.grey, x0, x1, 0);
		int shift = 0;
		bool ok = true;
		if (mad_best <= kGood || mad_best < 0.6 * mad_zero)
			shift = best;
		else if (mad_zero <= kGood)
			shift = 0;
		else
			ok = false; // content changed, not just moved

		cur.shift[static_cast<size_t>(k)] = shift;
		cur.ok[static_cast<size_t>(k)] = ok ? 1 : 0;
		if (ok && gap > 0) {
			const double v = shift / sy_ / gap;
			strip_vy_[static_cast<size_t>(k)] = 0.5 * strip_vy_[static_cast<size_t>(k)] + 0.5 * v;
		}
	}
}

void MotionTracker::set_anchor(Track &t, const Rect &box, const std::vector<Rect> &anchors, uint64_t seq) const
{
	// The old anchor's offset belongs to the old box; never keep it.
	t.has_anchor = false;
	t.anchor = Image();
	const Frame *f = frame_at(seq);
	if (!f || f->full.empty())
		return;
	for (const Rect &a : anchors) {
		const int cx = a.x + a.w / 2, cy = a.y + a.h / 2;
		if (cx < box.x || cx >= box.right() || cy < box.y || cy >= box.bottom())
			continue;
		const Rect c = a.clipped(static_cast<int>(f->full.width), static_cast<int>(f->full.height));
		if (c.w < 8 || c.h < 6)
			continue;
		t.anchor = crop(f->full, c);
		t.anchor_dx = c.x - box.x;
		t.anchor_dy = c.y - box.y;
		t.has_anchor = true;
		return;
	}
}

bool MotionTracker::hunt_anchor(Track &t, const Rect &cur, const Frame &from, const Frame &to, int pred_dy, Rect &next,
				int wide) const
{
	(void)from;
	const Image &img = to.full;
	const Image &tpl = t.anchor;
	const int ax = cur.x + t.anchor_dx;
	const int ay = cur.y + t.anchor_dy;
	const int W = static_cast<int>(img.width), H = static_cast<int>(img.height);
	const int tw = static_cast<int>(tpl.width), th = static_cast<int>(tpl.height);

	// Motion-shaped window: grow along the predicted motion, shrink behind.
	// When moving, extend along the motion and cut back behind it. When
	// (nearly) still, a scroll can start either way: search both ways.
	int dy0, dy1;
	if (std::abs(pred_dy) < 3) {
		dy0 = -wide;
		dy1 = wide;
	} else {
		const int grow = 24 + std::abs(pred_dy);
		const int shrink = 8;
		dy0 = pred_dy >= 0 ? -shrink : pred_dy - grow;
		dy1 = pred_dy >= 0 ? pred_dy + grow : shrink;
	}
	const int dx0 = -8, dx1 = 8;

	auto sad = [&](int dx, int dy, int stride) {
		const int x0 = ax + dx, y0 = ay + dy;
		if (x0 < 0 || y0 < 0 || x0 + tw > W || y0 + th > H)
			return std::numeric_limits<double>::infinity();
		uint64_t sum = 0, n = 0;
		for (int y = 0; y < th; y += stride) {
			const uint8_t *rt = tpl.pixels.data() + static_cast<size_t>(y) * tpl.width;
			const uint8_t *ri = img.pixels.data() + static_cast<size_t>(y0 + y) * img.width + x0;
			for (int x = 0; x < tw; x += stride) {
				sum += static_cast<uint64_t>(
					std::abs(static_cast<int>(rt[x]) - static_cast<int>(ri[x])));
				n++;
			}
		}
		return n ? static_cast<double>(sum) / static_cast<double>(n) : std::numeric_limits<double>::infinity();
	};

	// Coarse (every 2nd offset, every 2nd pixel), then refine at full detail.
	int bx = 0, by = pred_dy;
	double best = std::numeric_limits<double>::infinity();
	for (int dy = dy0; dy <= dy1; dy += 2)
		for (int dx = dx0; dx <= dx1; dx += 2) {
			const double e = sad(dx, dy, 2);
			if (e < best) {
				best = e;
				bx = dx;
				by = dy;
			}
		}
	if (std::isinf(best))
		return false;
	const int cx = bx, cy = by;
	best = std::numeric_limits<double>::infinity();
	for (int dy = cy - 2; dy <= cy + 2; dy++)
		for (int dx = cx - 2; dx <= cx + 2; dx++) {
			const double e = sad(dx, dy, 1);
			if (e < best) {
				best = e;
				bx = dx;
				by = dy;
			}
		}
	// A clean match of the same word stays well below this (anti-aliasing
	// and video compression only); anything else is "not found".
	if (best > 14.0) {
		return false;
	}

	next = cur;
	next.x += bx;
	next.y += by;
	const double gap = static_cast<double>(to.seq - from.seq);
	if (gap > 0) {
		t.st.vx = bx / gap;
		t.st.vy = by / gap;
	}
	return true;
}

int MotionTracker::strip_of(const Rect &r) const
{
	if (frames_.empty())
		return 0;
	const double W = frames_.back().grey.width;
	const double cx = (r.x + r.w / 2.0) * sx_;
	return std::clamp(static_cast<int>(cx * kStrips / W), 0, kStrips - 1);
}

bool MotionTracker::step(Track &t, const Frame &from, const Frame &to, bool forward)
{
	auto it = t.st.positions.find(from.seq);
	if (it == t.st.positions.end())
		return true;
	const Rect cur = it->second;

	// Shifts are stored on the later frame of each pair.
	const Frame &later = forward ? to : from;
	if (later.shift.size() != kStrips) {
		t.st.positions[to.seq] = cur;
		return true;
	}
	const int k = strip_of(cur);
	const int sign = forward ? 1 : -1;

	// Ultra track: find the anchor word again at full resolution, in a
	// window that extends along the predicted motion and is cut short on
	// the opposite side. Its displacement is the box's motion.
	if (forward && t.has_anchor && !from.full.empty() && !to.full.empty()) {
		// Predict from the anchor's own measured speed; the strip estimate is
		// only a second place to look (it can be fooled, the anchor less so).
		const int own = static_cast<int>(std::lround(t.st.vy * static_cast<double>(to.seq - from.seq)));
		const int strip = later.ok[static_cast<size_t>(k)]
					  ? static_cast<int>(std::lround(later.shift[static_cast<size_t>(k)] / sy_))
					  : own;
		Rect next;
		// Last resort before falling back to strips: one wide search.
		if (hunt_anchor(t, cur, from, to, own, next) ||
		    (strip != own && hunt_anchor(t, cur, from, to, strip, next)) ||
		    hunt_anchor(t, cur, from, to, 0, next, 160)) {
			t.st.positions[to.seq] = next;
			anchor_hits_++;
			return true;
		}
		anchor_misses_++;
	}

	// Candidates: this strip's motion, its neighbours' (a box can straddle
	// strips) and zero (fixed content inside a scrolling strip).
	std::vector<int> cands;
	for (int d : {0, -1, 1}) {
		const int kk = k + d;
		if (kk < 0 || kk >= kStrips || !later.ok[static_cast<size_t>(kk)])
			continue;
		cands.push_back(sign * later.shift[static_cast<size_t>(kk)]);
	}
	cands.push_back(0);

	const Rect patch = to_thumb(cur)
				   .padded(config_.context)
				   .clipped(static_cast<int>(from.grey.width), static_cast<int>(from.grey.height));
	int best = 0;
	double best_sad = std::numeric_limits<double>::infinity();
	for (int dy : cands) {
		const double sad = patch_sad(from.grey, to.grey, patch, 0, dy);
		if (sad < best_sad - 0.25) {
			best_sad = sad;
			best = dy;
		}
	}

	bool ok = true;
	if (std::isinf(best_sad)) {
		// Patch (partly) left the frame: trust the strip's motion.
		best = later.ok[static_cast<size_t>(k)] ? sign * later.shift[static_cast<size_t>(k)] : 0;
	} else if (best_sad > config_.lost_threshold) {
		best = 0;
		ok = false; // the text under the box changed
	}

	Rect next = cur;
	next.y += static_cast<int>(std::lround(best / sy_));
	t.st.positions[to.seq] = next;
	return ok;
}

void MotionTracker::propagate_forward(Track &t, uint64_t from_seq)
{
	const Frame *prev = nullptr;
	for (const Frame &f : frames_) {
		if (f.seq > from_seq && prev && t.st.positions.count(prev->seq)) {
			if (!step(t, *prev, f, true))
				rescan_requested_ = true;
		}
		prev = &f;
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

void MotionTracker::add_frame_full(uint64_t seq, uint64_t ts, Image grey_full)
{
	if (grey_full.empty() || grey_full.channels != 1)
		return;
	const uint32_t fw = grey_full.width, fh = grey_full.height;
	// Strip thumbnail: halve (2x2 average) until at most ~1000 px wide.
	// Cheap compared to a generic resample, which matters at 30-60 fps.
	Image thumb = grey_full;
	while (thumb.width > 1000 && thumb.height >= 2) {
		Image h;
		h.width = thumb.width / 2;
		h.height = thumb.height / 2;
		h.channels = 1;
		h.pixels.resize(static_cast<size_t>(h.width) * h.height);
		for (uint32_t y = 0; y < h.height; y++) {
			const uint8_t *r0 = thumb.pixels.data() + static_cast<size_t>(2 * y) * thumb.width;
			const uint8_t *r1 = r0 + thumb.width;
			uint8_t *o = h.pixels.data() + static_cast<size_t>(y) * h.width;
			for (uint32_t x = 0; x < h.width; x++)
				o[x] = static_cast<uint8_t>(
					(r0[2 * x] + r0[2 * x + 1] + r1[2 * x] + r1[2 * x + 1] + 2) >> 2);
		}
		thumb = std::move(h);
	}
	add_frame(seq, ts, std::move(thumb), fw, fh, std::move(grey_full));
}

void MotionTracker::add_frame(uint64_t seq, uint64_t ts, Image grey, uint32_t full_w, uint32_t full_h, Image full)
{
	if (grey.empty() || grey.channels != 1 || full_w == 0 || full_h == 0)
		return;
	if (full_w != full_w_ || full_h != full_h_ ||
	    (!frames_.empty() &&
	     (frames_.back().grey.width != grey.width || frames_.back().grey.height != grey.height))) {
		clear();
		full_w_ = full_w;
		full_h_ = full_h;
	}
	sx_ = static_cast<double>(grey.width) / full_w;
	sy_ = static_cast<double>(grey.height) / full_h;
	if (!frames_.empty() && seq <= frames_.back().seq)
		return; // out of order, ignore

	Frame f{seq, ts, std::move(grey), {}, {}, std::move(full)};
	if (!frames_.empty())
		measure_strips(frames_.back(), f);
	frames_.push_back(std::move(f));
	if (have_verified_) {
		const Frame &nf = frames_.back();
		for (size_t k = 0; k < nf.shift.size() && k < cum_shift_.size(); k++)
			if (nf.ok[k])
				cum_shift_[k] += nf.shift[k];
		update_unverified(nf);
	}
	// Full-resolution copies are only needed for recent frames (anchor
	// hunting and re-anchoring late scans); free older ones.
	constexpr size_t kKeepFull = 48;
	if (frames_.size() > kKeepFull) {
		Image &old = frames_[frames_.size() - 1 - kKeepFull].full;
		if (!old.pixels.empty())
			old = Image();
	}
	const Frame &cur = frames_.back();
	const Frame *prev = frames_.size() > 1 ? &frames_[frames_.size() - 2] : nullptr;

	for (Track &t : tracks_) {
		if (t.st.positions.empty())
			continue;
		auto last = t.st.positions.rbegin();
		if (last->first >= seq)
			continue;
		if (prev && last->first == prev->seq) {
			if (!step(t, *prev, cur, true))
				rescan_requested_ = true;
		} else {
			t.st.positions[seq] = last->second;
		}
	}

	// Scans that were waiting for this frame.
	if (!pending_scans_.empty()) {
		std::vector<Scan> ready;
		std::vector<Scan> waiting;
		for (Scan &sc : pending_scans_)
			(sc.seq <= seq ? ready : waiting).push_back(std::move(sc));
		pending_scans_ = std::move(waiting);
		for (Scan &sc : ready)
			apply_scan(std::move(sc));
	}

	prune();
}

void MotionTracker::add_scan(uint64_t seq, std::vector<Rect> rects, std::vector<Rect> anchors)
{
	Scan sc{seq, std::move(rects), {}, false, std::move(anchors)};
	if (frames_.empty() || seq > frames_.back().seq) {
		pending_scans_.push_back(std::move(sc));
		return;
	}
	apply_scan(std::move(sc));
}

void MotionTracker::add_partial_scan(uint64_t seq, std::vector<Rect> rects, std::vector<Rect> regions,
				     std::vector<Rect> anchors)
{
	Scan sc{seq, std::move(rects), std::move(regions), true, std::move(anchors)};
	if (frames_.empty() || seq > frames_.back().seq) {
		pending_scans_.push_back(std::move(sc));
		return;
	}
	apply_scan(std::move(sc));
}

void MotionTracker::apply_scan(Scan scan)
{
	// If OCR took longer than the history, anchor to the oldest frame we have.
	uint64_t seq = scan.seq;
	if (!frames_.empty() && seq < frames_.front().seq)
		seq = frames_.front().seq;
	const Frame *frame = frame_at(seq);
	const uint64_t scan_ts = frame ? frame->ts : (frames_.empty() ? 0 : frames_.back().ts);

	if (scan.partial) {
		if (scan.seq <= newest_partial_seq_ || (any_scan_ && scan.seq <= newest_scan_seq_))
			return; // stale
		newest_partial_seq_ = scan.seq;
	} else {
		if (any_scan_ && scan.seq <= newest_scan_seq_)
			return; // stale (older than a scan already applied)
		prev_scan_seq_ = any_scan_ ? newest_scan_seq_ : (frames_.empty() ? seq : frames_.front().seq);
		newest_scan_seq_ = scan.seq;
		any_scan_ = true;
	}
	auto in_regions = [&](const Rect &r) {
		for (const Rect &g : scan.regions)
			if (g.intersects(r))
				return true;
		return false;
	};
	auto region_of = [&](const Rect &r) -> int {
		for (size_t i = 0; i < scan.regions.size(); i++)
			if (scan.regions[i].intersects(r))
				return static_cast<int>(i);
		return -1;
	};

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
			// Targeted scan: the box may have moved further than predicted
			// but is still inside the window searched for it; take the
			// nearest box predicted in the same window.
			if (score == 0.0 && scan.partial && region_of(p) >= 0 && region_of(p) == region_of(d)) {
				const double dy = std::fabs((p.y + p.h / 2.0) - (d.y + d.h / 2.0));
				score = 0.005 / (1.0 + dy);
			}
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
			set_anchor(t, d, scan.anchors, seq);
			propagate_forward(t, seq);
		} else {
			Track t;
			t.st.positions[seq] = d;
			set_anchor(t, d, scan.anchors, seq);
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

	if (!scan.partial)
		set_verified(seq);

	// Tracks this scan should have seen but did not.
	for (size_t i = 0; i < matched_track.size() && i < tracks_.size(); i++) {
		if (matched_track[i])
			continue;
		Track &t = tracks_[i];
		if (t.st.positions.empty() || t.st.positions.begin()->first > seq)
			continue;
		if (scan.partial) {
			// Only boxes whose search window was read can be missed.
			auto it = t.st.positions.upper_bound(seq);
			--it;
			if (!in_regions(it->second))
				continue;
		}
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
	for (double v : strip_vy_)
		m = std::max(m, std::fabs(v));
	return m;
}

void MotionTracker::set_verified(uint64_t seq)
{
	const Frame *f = frame_at(seq);
	if (!f)
		return;
	verified_img_ = f->grey;
	cum_shift_.assign(kStrips, 0);
	// Motion since the scanned frame (frames already processed).
	for (const Frame &later : frames_) {
		if (later.seq <= seq)
			continue;
		for (size_t k = 0; k < later.shift.size() && k < cum_shift_.size(); k++)
			if (later.ok[k])
				cum_shift_[k] += later.shift[k];
	}
	have_verified_ = true;
	if (!frames_.empty())
		update_unverified(frames_.back());
}

void MotionTracker::update_unverified(const Frame &f)
{
	unverified_.clear();
	const Image &cur = f.grey;
	const Image &ref = verified_img_;
	if (cur.width != ref.width || cur.height != ref.height || cur.empty())
		return;
	const int W = static_cast<int>(cur.width), H = static_cast<int>(cur.height);
	constexpr int kCell = 16;
	for (int cy = 0; cy < H; cy += kCell) {
		int run_start = -1;
		for (int cx = 0; cx <= W; cx += kCell) {
			bool dirty = false;
			if (cx < W) {
				const int k = std::clamp(cx * kStrips / W, 0, kStrips - 1);
				const int sh = cum_shift_.empty() ? 0 : cum_shift_[static_cast<size_t>(k)];
				uint64_t sum = 0, n = 0;
				for (int y = cy; y < std::min(H, cy + kCell) && !dirty; y += 2) {
					const int py = y - sh;
					if (py < 0 || py >= H) {
						dirty = true; // content that scrolled in since the scan
						break;
					}
					const uint8_t *rc = cur.pixels.data() + static_cast<size_t>(y) * cur.width;
					const uint8_t *rr = ref.pixels.data() + static_cast<size_t>(py) * ref.width;
					for (int x = cx; x < std::min(W, cx + kCell); x += 2) {
						sum += static_cast<uint64_t>(
							std::abs(static_cast<int>(rc[x]) - static_cast<int>(rr[x])));
						n++;
					}
				}
				if (!dirty && n && static_cast<double>(sum) / static_cast<double>(n) > 6.0)
					dirty = true; // content changed since the scan
			}
			if (dirty && run_start < 0)
				run_start = cx;
			if (!dirty && run_start >= 0) {
				// Cell run [run_start, cx) on this row -> full resolution.
				const Rect thumb{run_start, cy, cx - run_start, std::min(kCell, H - cy)};
				unverified_.push_back(thumb.scaled(1.0 / sx_, 1.0 / sy_));
				run_start = -1;
			}
		}
	}
	unverified_ = merge_rects(std::move(unverified_));
}

TrackerView MotionTracker::view(uint64_t from_seq) const
{
	TrackerView v;
	v.verified_any = have_verified_;
	v.unverified = unverified_;
	v.newest_scan_seq = newest_scan_seq_;
	v.any_scan = any_scan_;
	v.persist_ns = config_.persist_ns;
	v.tracks.reserve(tracks_.size());
	for (const Track &t : tracks_) {
		TrackState s;
		// Boxes extrapolate with their strip's (smoothed) scroll speed.
		s.vx = 0.0;
		s.vy = 0.0;
		if (t.has_anchor)
			s.vy = t.st.vy; // measured from the anchor word itself
		else if (!t.st.positions.empty() && strip_vy_.size() == kStrips)
			s.vy = strip_vy_[static_cast<size_t>(strip_of(t.st.positions.rbegin()->second))];
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
