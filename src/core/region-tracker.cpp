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
	std::vector<Rect> out;
	const size_t n = results_.size();
	for (size_t i = 0; i < n; i++) {
		const Result &r = results_[i];
		if (r.regions.empty())
			continue;

		uint64_t start = r.ts > persist_ns_ ? r.ts - persist_ns_ : 0;
		if (i > 0)
			start = std::min(start, results_[i - 1].ts);
		if (frame_ts_ns < start)
			continue;

		const size_t expiry_scan = i + 1 + misses_;
		if (expiry_scan < n && frame_ts_ns > results_[expiry_scan].ts + persist_ns_)
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
	// The front result is dead once its expiry scan is older than the oldest
	// frame we may still output. Keep one extra result as the "previous scan"
	// that bounds the look-ahead of its successor.
	const size_t expiry_offset = 1 + misses_;
	while (results_.size() > expiry_offset + 1 && results_[expiry_offset].ts + persist_ns_ < oldest_needed_ts_ns &&
	       results_[1].ts < oldest_needed_ts_ns)
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
