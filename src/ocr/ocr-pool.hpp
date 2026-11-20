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

// A fixed set of OCR threads, each owning its own engine instance (engines
// are not thread safe, and WinRT / Tesseract state is per thread).

#include "ocr-engine.hpp"

#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace pii {

class OcrPool {
public:
	// Starts `threads` workers and waits until every engine is initialised.
	OcrPool(const OcrConfig &config, size_t threads);
	~OcrPool();

	OcrPool(const OcrPool &) = delete;
	OcrPool &operator=(const OcrPool &) = delete;

	bool ok() const { return ok_; }
	const std::string &error() const { return error_; }
	const std::string &engine_name() const { return engine_name_; }
	size_t size() const { return threads_.size(); }

	// Recognise every image in parallel; blocks until all are done.
	std::vector<std::vector<OcrLine>> run(const std::vector<const Image *> &images);

private:
	void worker(OcrConfig config);

	std::vector<std::thread> threads_;
	std::mutex mutex_;
	std::condition_variable work_cv_;
	std::condition_variable done_cv_;

	// Initialisation
	size_t started_ = 0;
	bool ok_ = true;
	std::string error_;
	std::string engine_name_;

	// Current batch
	uint64_t generation_ = 0;
	bool stopping_ = false;
	const std::vector<const Image *> *tasks_ = nullptr;
	std::vector<std::vector<OcrLine>> *results_ = nullptr;
	size_t next_ = 0;
	size_t remaining_ = 0;
};

} // namespace pii
