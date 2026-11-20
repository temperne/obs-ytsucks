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
// OCR is far slower than the frame rate, so results are always late. To
// reduce flicker and leaks every result is kept for `persist_ns` and a frame
// at time T is covered by every result produced from a frame captured at or
// after T - persist_ns. When the filter delays its output (zero-leak mode)
// this naturally includes results from frames captured *after* T ("look
// ahead"), which is what closes the gap between text appearing and OCR
// noticing it.
//
// Not thread safe; the filter guards it with a mutex.
class RegionTracker {
public:
	void set_persistence_ns(uint64_t ns) { persist_ns_ = ns; }

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
	uint64_t newest_seq_ = 0;
	bool have_any_ = false;
};

// Merge overlapping (or touching) rectangles until none overlap.
std::vector<Rect> merge_rects(std::vector<Rect> rects);

} // namespace pii
