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

#include "ocr-engine.hpp"

namespace pii {

#ifdef PII_HAVE_TESSERACT
std::unique_ptr<OcrEngine> create_tesseract_engine(const OcrConfig &config, std::string &error);
#endif
#ifdef PII_HAVE_WINRT_OCR
std::unique_ptr<OcrEngine> create_windows_ocr_engine(const OcrConfig &config, std::string &error);
#endif
#ifdef PII_HAVE_APPLE_VISION
std::unique_ptr<OcrEngine> create_apple_vision_engine(const OcrConfig &config, std::string &error);
#endif

std::vector<OcrBackend> available_ocr_backends()
{
	std::vector<OcrBackend> list;
#ifdef PII_HAVE_WINRT_OCR
	list.push_back(OcrBackend::WindowsMediaOcr);
#endif
#ifdef PII_HAVE_APPLE_VISION
	list.push_back(OcrBackend::AppleVision);
#endif
#ifdef PII_HAVE_TESSERACT
	list.push_back(OcrBackend::Tesseract);
#endif
	return list;
}

const char *ocr_backend_id(OcrBackend backend)
{
	switch (backend) {
	case OcrBackend::Auto:
		return "auto";
	case OcrBackend::Tesseract:
		return "tesseract";
	case OcrBackend::WindowsMediaOcr:
		return "windows";
	case OcrBackend::AppleVision:
		return "vision";
	}
	return "auto";
}

OcrBackend ocr_backend_from_id(const std::string &id)
{
	if (id == "tesseract")
		return OcrBackend::Tesseract;
	if (id == "windows")
		return OcrBackend::WindowsMediaOcr;
	if (id == "vision")
		return OcrBackend::AppleVision;
	return OcrBackend::Auto;
}

std::unique_ptr<OcrEngine> create_ocr_engine(const OcrConfig &config, std::string &error)
{
	OcrBackend backend = config.backend;
	if (backend == OcrBackend::Auto) {
		const auto list = available_ocr_backends();
		if (list.empty()) {
			error = "this build contains no OCR backend";
			return nullptr;
		}
		backend = list.front();
	}

	switch (backend) {
#ifdef PII_HAVE_TESSERACT
	case OcrBackend::Tesseract:
		return create_tesseract_engine(config, error);
#endif
#ifdef PII_HAVE_WINRT_OCR
	case OcrBackend::WindowsMediaOcr:
		return create_windows_ocr_engine(config, error);
#endif
#ifdef PII_HAVE_APPLE_VISION
	case OcrBackend::AppleVision:
		return create_apple_vision_engine(config, error);
#endif
	default:
		break;
	}
	error = std::string("OCR backend '") + ocr_backend_id(backend) + "' is not available in this build";
	return nullptr;
}

} // namespace pii
