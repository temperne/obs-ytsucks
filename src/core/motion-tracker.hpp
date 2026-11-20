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

#pragma once

// Keeps redaction boxes glued to the content between OCR scans.
//
// Motion is measured per vertical *strip* of the frame, not per box: each
// strip's scroll offset between two samples is found by matching full-height
// row profiles (headings, paragraph gaps and images make these unambiguous,
// unlike a single line of text which looks like its neighbours). Every box
// in a strip then moves by the same amount, so boxes move together with the
// page and cannot wander off on their own. Per box we only choose between
// a few candidate offsets (its strip's, its neighbours', or zero for fixed
// content such as toolbars), which cannot alias onto another text line.
//
// OCR is much slower than the frame rate, and when a page scrolls a box
// placed where the text *was* stops covering it. The tracker receives a
// small grey thumbnail of *some* frames (the filter samples a few times per
// second, more often while things move, and always the frame OCR scanned)
// and, for each box, finds where its image patch moved between samples
// (block matching, sum of absolute differences). That yields a velocity per
// box; frames between samples are extrapolated with it and the box is
// widened along the motion (see TrackerView::rects_for).
//
// Latency compensation: a scan of frame s arrives some time later. Its
// boxes are re-anchored at s and carried forward through the samples taken
// since, so they land where the content is *now*.
//
// Box lifetime (the "remove only once it is gone" rule):
//   * an OCR scan that finds a box again re-anchors it to the exact OCR rect;
//   * a box is only retired after `tolerated_misses + 1` consecutive scans
//     did not find it, and stays `persist_ns` longer after that;
//   * if tracking loses the content (patch no longer matches anything) the
//     box stays where it is and `take_rescan_request()` asks for an
//     immediate rescan.
//
// When the output is delayed, a new box is also propagated *backwards* to
// the previous scan, so the frames between "text appeared" and "OCR saw it"
// are covered as well.
//
// Single threaded. The filter runs it on its own thread and hands the
// render thread a TrackerView snapshot.

#include "image.hpp"
#include "pii-types.hpp"

#include <cstdint>
#include <deque>
#include <map>
#include <vector>

namespace pii {

struct MotionConfig {
	uint64_t persist_ns = 1500000000ULL;
	size_t tolerated_misses = 1;
	int search_radius = 16;       // thumbnail pixels per video frame between samples
	int max_search_radius = 64;   // cap when samples are several frames apart
	int context = 3;              // thumbnail pixels of context around each patch
	double lost_threshold = 28.0; // mean abs grey difference per pixel
	size_t history_frames = 300;
	// New boxes are carried back at least this many frames (set to the
	// output delay), so text that was not yet readable (e.g. still cut off
	// at the edge while scrolling in) is covered on delayed frames too.
	uint64_t lookback_frames = 0;
};

struct TrackState {
	std::map<uint64_t, Rect> positions; // frame seq -> full-resolution rect
	double vx = 0.0;                    // full-resolution pixels per frame
	double vy = 0.0;
	bool dead = false;
	uint64_t dead_ts = 0;
};

// What the render thread needs to place boxes on a given output frame.
struct TrackerView {
	std::vector<TrackState> tracks;
	uint64_t newest_scan_seq = 0;
	bool any_scan = false;
	uint64_t persist_ns = 0;

	// Boxes for the frame `seq` captured at `ts`. Frames newer than the
	// tracker has seen are extrapolated with each box's velocity (and the
	// box grows in the direction of motion to absorb the guess).
	std::vector<Rect> rects_for(uint64_t seq, uint64_t ts) const;
	bool verified(uint64_t seq) const { return any_scan && newest_scan_seq >= seq; }
};

class MotionTracker {
public:
	explicit MotionTracker(const MotionConfig &config = MotionConfig());

	void set_config(const MotionConfig &config) { config_ = config; }
	const MotionConfig &config() const { return config_; }

	// Add the thumbnail (1 channel) of captured frame `seq`. `full_w/h` is
	// the source resolution the boxes are expressed in.
	void add_frame(uint64_t seq, uint64_t ts, Image grey_thumb, uint32_t full_w, uint32_t full_h);

	// OCR found `rects` (full resolution) in frame `seq`. May arrive before
	// that frame's thumbnail; it is then applied when the thumbnail comes.
	void add_scan(uint64_t seq, std::vector<Rect> rects);

	// Snapshot holding positions for frames >= from_seq.
	TrackerView view(uint64_t from_seq) const;

	// True once after tracking lost a box (content changed under it).
	bool take_rescan_request();

	size_t track_count() const { return tracks_.size(); }
	// Fastest box motion (full-res pixels per video frame) among live tracks.
	double max_speed() const;
	uint64_t newest_frame_seq() const { return frames_.empty() ? 0 : frames_.back().seq; }
	void clear();

private:
	struct Frame {
		uint64_t seq;
		uint64_t ts;
		Image grey;
		// Vertical content shift of each strip relative to the previous
		// sample, in thumbnail rows (content at y came from y - shift), and
		// whether that strip's motion could be confirmed.
		std::vector<int> shift;
		std::vector<uint8_t> ok;
	};
	struct Track {
		TrackState st;
		size_t misses = 0;
	};
	struct Scan {
		uint64_t seq;
		std::vector<Rect> rects;
	};

	const Frame *frame_at(uint64_t seq) const;
	void apply_scan(Scan scan);
	// Move a track's box from frame `from` to frame `to` (adjacent in either
	// direction). Returns false when the content was lost.
	bool step(Track &t, const Frame &from, const Frame &to, bool forward);
	void measure_strips(const Frame &prev, Frame &cur);
	int strip_of(const Rect &full_rect) const;
	void propagate_forward(Track &t, uint64_t from_seq);
	void propagate_backward(Track &t, uint64_t from_seq, uint64_t to_seq);
	void prune();

	Rect to_thumb(const Rect &r) const;

	MotionConfig config_;
	std::deque<Frame> frames_;
	std::vector<Track> tracks_;
	std::vector<Scan> pending_scans_;
	uint32_t full_w_ = 0;
	uint32_t full_h_ = 0;
	double sx_ = 1.0; // thumb / full
	double sy_ = 1.0;
	uint64_t newest_scan_seq_ = 0;
	uint64_t prev_scan_seq_ = 0;
	bool any_scan_ = false;
	bool rescan_requested_ = false;
	// Smoothed vertical velocity per strip, full-res px per video frame.
	std::vector<double> strip_vy_;
};

// Block matching, exposed for tests. Finds (dx, dy) minimising the mean
// absolute difference between `patch` in `a` and the shifted patch in `b`,
// searching +-radius around (pred_dx, pred_dy). `error` receives the mean
// absolute difference of the result (or a negative value when the patch
// left the image and the prediction was returned unchanged).
void match_patch(const Image &a, const Image &b, const Rect &patch, int pred_dx, int pred_dy, int radius, int &dx,
		 int &dy, double &error);

} // namespace pii
