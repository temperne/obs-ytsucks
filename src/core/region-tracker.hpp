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

#include "pii-types.hpp"

#include <cstdint>
#include <deque>
#include <vector>

namespace pii {

// Keeps the results of recent analyses and decides which rectangles cover a
// given output frame.
//
// OCR is far slower than the frame rate, so results are always late. Time is
// measured in *capture* timestamps of the scanned frames, never in "when the
// result arrived", so slow scans cannot shorten how long a box is shown.
//
// A region found by scan k (frame captured at t_k) covers every output frame
// captured in
//
//     [ min(t_{k-1}, t_k - persist),  t_{k+1+misses} + persist ]
//
// * Start: the text was not seen by scan k-1, so it appeared some time after
//   t_{k-1}; with a delayed output (zero-leak mode) those earlier frames get
//   covered too ("look ahead").
// * End: the region is held until `misses + 1` later scans have *completed*
//   (and then `persist` longer). Until then it is held indefinitely, however
//   long the scans take. So boxes never blink off between scans, and one
//   OCR miss (`misses` = 1 by default) does not uncover the text.
//
// Not thread safe; the filter guards it with a mutex.
class RegionTracker {
public:
	void set_persistence_ns(uint64_t ns) { persist_ns_ = ns; }
	// Number of consecutive later scans allowed to miss a region before it
	// starts to expire.
	void set_tolerated_misses(size_t n) { misses_ = n; }

	// Record the regions found in the frame captured at `frame_ts_ns`.
	void add_result(uint64_t frame_seq, uint64_t frame_ts_ns, std::vector<Rect> regions);

	// Regions that must be covered when outputting the frame captured at
	// `frame_ts_ns`. Overlapping rectangles are merged.
	std::vector<Rect> regions_for(uint64_t frame_ts_ns) const;

	// True when an analysis of this frame or a later one has completed,
	// i.e. the output of this frame has been "looked at".
	bool verified(uint64_t frame_seq) const;

	// Drop results that can no longer influence any frame captured at or
	// after `oldest_needed_ts_ns`.
	void prune(uint64_t oldest_needed_ts_ns);

	void clear();

	size_t result_count() const { return results_.size(); }

private:
	struct Result {
		uint64_t seq;
		uint64_t ts;
		std::vector<Rect> regions;
	};
	std::deque<Result> results_;
	uint64_t persist_ns_ = 1000000000ULL;
	size_t misses_ = 1;
	uint64_t newest_seq_ = 0;
	bool have_any_ = false;
};

// Merge overlapping (or touching) rectangles until none overlap.
std::vector<Rect> merge_rects(std::vector<Rect> rects);

} // namespace pii
