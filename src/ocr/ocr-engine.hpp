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

// Pluggable OCR backends. Each backend turns a BGRA frame into lines of words
// with pixel bounding boxes. Backends are created and used exclusively on the
// filter's analysis thread, so they need not be thread safe.

#include "../core/image.hpp"
#include "../core/pii-types.hpp"

#include <memory>
#include <string>
#include <vector>

namespace pii {

enum class OcrBackend {
	Auto, // best available: platform OCR on Windows/macOS, Tesseract elsewhere
	Tesseract,
	WindowsMediaOcr,
	AppleVision,
};

struct OcrConfig {
	OcrBackend backend = OcrBackend::Auto;
	// Language. Tesseract: "eng", "eng+deu"... Windows / Apple: BCP-47 tag
	// such as "en-US". Empty = backend default (user profile language /
	// "eng").
	std::string language;
	// Directory containing *.traineddata (Tesseract only). Empty = bundled
	// data, then TESSDATA_PREFIX.
	std::string tessdata_path;
	// Apple Vision: prefer speed over accuracy.
	bool fast_mode = false;
};

class OcrEngine {
public:
	virtual ~OcrEngine() = default;
	virtual const char *name() const = 0;
	// Returns lines in the coordinate space of `bgra`.
	virtual std::vector<OcrLine> recognize(const Image &bgra) = 0;
};

// Returns nullptr and fills `error` when the requested backend is not
// compiled in or fails to initialise.
std::unique_ptr<OcrEngine> create_ocr_engine(const OcrConfig &config, std::string &error);

// Backends compiled into this build, for the settings UI.
std::vector<OcrBackend> available_ocr_backends();
const char *ocr_backend_id(OcrBackend backend);
OcrBackend ocr_backend_from_id(const std::string &id);

} // namespace pii
