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

#include "ocr-pool.hpp"

#include <algorithm>

namespace pii {

OcrPool::OcrPool(const OcrConfig &config, size_t threads)
{
	threads = std::max<size_t>(1, std::min<size_t>(threads, 32));
	for (size_t i = 0; i < threads; i++)
		threads_.emplace_back(&OcrPool::worker, this, config);

	std::unique_lock<std::mutex> lock(mutex_);
	done_cv_.wait(lock, [&] { return started_ == threads; });
}

OcrPool::~OcrPool()
{
	{
		std::lock_guard<std::mutex> lock(mutex_);
		stopping_ = true;
	}
	work_cv_.notify_all();
	for (std::thread &t : threads_)
		t.join();
}

void OcrPool::worker(OcrConfig config)
{
	std::string err;
	std::unique_ptr<OcrEngine> engine = create_ocr_engine(config, err);
	uint64_t seen_generation = 0;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		if (!engine) {
			ok_ = false;
			if (error_.empty())
				error_ = err;
		} else if (engine_name_.empty()) {
			engine_name_ = engine->name();
		}
		started_++;
		seen_generation = generation_;
	}
	done_cv_.notify_all();

	for (;;) {
		{
			std::unique_lock<std::mutex> lock(mutex_);
			work_cv_.wait(lock, [&] { return stopping_ || generation_ != seen_generation; });
			if (stopping_)
				break;
			seen_generation = generation_;
		}

		// Claim work items under the lock so a late-waking worker can never
		// touch a batch that run() has already returned.
		for (;;) {
			const Image *image = nullptr;
			std::vector<OcrLine> *slot = nullptr;
			{
				std::lock_guard<std::mutex> lock(mutex_);
				if (generation_ != seen_generation || !tasks_ || next_ >= tasks_->size())
					break;
				const size_t i = next_++;
				image = (*tasks_)[i];
				slot = &(*results_)[i];
			}
			std::vector<OcrLine> lines;
			if (engine && image)
				lines = engine->recognize(*image);
			std::lock_guard<std::mutex> lock(mutex_);
			*slot = std::move(lines);
			if (--remaining_ == 0)
				done_cv_.notify_all();
		}
	}
}

std::vector<std::vector<OcrLine>> OcrPool::run(const std::vector<const Image *> &images)
{
	std::vector<std::vector<OcrLine>> results(images.size());
	if (images.empty() || !ok_)
		return results;

	std::unique_lock<std::mutex> lock(mutex_);
	tasks_ = &images;
	results_ = &results;
	next_ = 0;
	remaining_ = images.size();
	generation_++;
	work_cv_.notify_all();
	done_cv_.wait(lock, [&] { return remaining_ == 0; });
	tasks_ = nullptr;
	results_ = nullptr;
	return results;
}

} // namespace pii
