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

#include "region-tracker.hpp"

#include <algorithm>
#include <utility>

namespace pii {

void RegionTracker::add_result(uint64_t frame_seq, uint64_t frame_ts_ns, std::vector<Rect> regions)
{
	// Results normally arrive in order; keep the deque sorted by timestamp
	// anyway so pruning stays correct.
	Result r{frame_seq, frame_ts_ns, std::move(regions)};
	auto pos = std::upper_bound(results_.begin(), results_.end(), frame_ts_ns,
				    [](uint64_t ts, const Result &e) { return ts < e.ts; });
	results_.insert(pos, std::move(r));

	if (!have_any_ || frame_seq > newest_seq_)
		newest_seq_ = frame_seq;
	have_any_ = true;
}

std::vector<Rect> RegionTracker::regions_for(uint64_t frame_ts_ns) const
{
	const uint64_t from = frame_ts_ns > persist_ns_ ? frame_ts_ns - persist_ns_ : 0;
	std::vector<Rect> out;
	for (const Result &r : results_) {
		if (r.ts < from)
			continue;
		out.insert(out.end(), r.regions.begin(), r.regions.end());
	}
	return merge_rects(std::move(out));
}

bool RegionTracker::verified(uint64_t frame_seq) const
{
	return have_any_ && newest_seq_ >= frame_seq;
}

void RegionTracker::prune(uint64_t oldest_needed_ts_ns)
{
	const uint64_t keep_from = oldest_needed_ts_ns > persist_ns_ ? oldest_needed_ts_ns - persist_ns_ : 0;
	while (!results_.empty() && results_.front().ts < keep_from)
		results_.pop_front();
}

void RegionTracker::clear()
{
	results_.clear();
	newest_seq_ = 0;
	have_any_ = false;
}

std::vector<Rect> merge_rects(std::vector<Rect> rects)
{
	rects.erase(std::remove_if(rects.begin(), rects.end(), [](const Rect &r) { return r.empty(); }), rects.end());

	bool merged = true;
	while (merged) {
		merged = false;
		for (size_t i = 0; i < rects.size() && !merged; i++) {
			for (size_t j = i + 1; j < rects.size(); j++) {
				if (rects[i].padded(1).intersects(rects[j])) {
					rects[i] = rects[i].united(rects[j]);
					rects.erase(rects.begin() + static_cast<std::ptrdiff_t>(j));
					merged = true;
					break;
				}
			}
		}
	}
	return rects;
}

} // namespace pii
