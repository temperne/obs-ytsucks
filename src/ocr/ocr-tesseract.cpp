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

// Tesseract backend (all platforms). Enabled with -DENABLE_TESSERACT=ON.

#include "ocr-engine.hpp"

#include <tesseract/baseapi.h>
#include <tesseract/resultiterator.h>

#include <cstdlib>

namespace pii {

namespace {

class TesseractEngine : public OcrEngine {
public:
	bool init(const OcrConfig &config, std::string &error)
	{
		const std::string lang = config.language.empty() ? "eng" : config.language;
		const char *datapath = config.tessdata_path.empty() ? nullptr : config.tessdata_path.c_str();
		if (api_.Init(datapath, lang.c_str(), tesseract::OEM_LSTM_ONLY) != 0) {
			error = "Tesseract could not load language '" + lang + "' from '" +
				(datapath ? config.tessdata_path : std::string("TESSDATA_PREFIX/default")) + "'";
			return false;
		}
		// Screens contain scattered text (UI, browser pages, chat...).
		api_.SetPageSegMode(tesseract::PSM_SPARSE_TEXT);
		// Dictionaries "correct" numbers and addresses away; turn them off.
		api_.SetVariable("load_system_dawg", "0");
		api_.SetVariable("load_freq_dawg", "0");
		return true;
	}

	const char *name() const override { return "Tesseract"; }

	std::vector<OcrLine> recognize(const Image &bgra) override
	{
		std::vector<OcrLine> lines;
		const Image grey = to_grey(bgra);
		if (grey.empty())
			return lines;

		api_.SetImage(grey.pixels.data(), static_cast<int>(grey.width), static_cast<int>(grey.height), 1,
			      static_cast<int>(grey.stride()));
		api_.SetSourceResolution(96);
		if (api_.Recognize(nullptr) != 0)
			return lines;

		tesseract::ResultIterator *it = api_.GetIterator();
		if (!it)
			return lines;

		const tesseract::PageIteratorLevel level = tesseract::RIL_WORD;
		do {
			if (it->Empty(level))
				continue;
			if (lines.empty() || it->IsAtBeginningOf(tesseract::RIL_TEXTLINE))
				lines.emplace_back();

			char *text = it->GetUTF8Text(level);
			if (!text)
				continue;
			int l = 0, t = 0, r = 0, b = 0;
			if (it->BoundingBox(level, &l, &t, &r, &b)) {
				OcrWord w;
				w.text = text;
				w.box = {l, t, r - l, b - t};
				w.confidence = it->Confidence(level);
				lines.back().words.push_back(std::move(w));
			}
			delete[] text;
		} while (it->Next(level));
		delete it;

		api_.Clear();
		return lines;
	}

	~TesseractEngine() override { api_.End(); }

private:
	tesseract::TessBaseAPI api_;
};

} // namespace

std::unique_ptr<OcrEngine> create_tesseract_engine(const OcrConfig &config, std::string &error)
{
	auto engine = std::make_unique<TesseractEngine>();
	if (!engine->init(config, error))
		return nullptr;
	return engine;
}

} // namespace pii
