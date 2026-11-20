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
#include <tesseract/ocrclass.h>
#include <tesseract/resultiterator.h>

#include <cstdlib>

#ifndef _WIN32
#include <dlfcn.h>
#endif

namespace pii {

namespace {

// Distribution builds of Tesseract use OpenMP. We already run one engine per
// thread; letting every engine also start its own OpenMP team makes the
// threads spin against each other (a 25 ms band can take 20 s). The usual
// fix, OMP_THREAD_LIMIT=1, only works if set before libgomp is loaded,
// which happens before our module code runs. Instead switch parallel
// regions off at runtime: with max-active-levels = 0 every region runs on
// the calling thread. Looked up dynamically so builds without OpenMP work.
// Must run on every thread that calls into Tesseract: in current OpenMP
// max-active-levels is a per-thread ("data environment") setting.
void disable_openmp_parallelism()
{
#ifndef _WIN32
	using SetLevels = void (*)(int);
	static SetLevels fn = [] {
		SetLevels f = nullptr;
		for (const char *lib : {"libgomp.so.1", "libgomp.1.dylib", "libomp.so", "libomp.dylib"}) {
			void *h = dlopen(lib, RTLD_LAZY | RTLD_NOLOAD);
			if (!h)
				continue;
			f = reinterpret_cast<SetLevels>(dlsym(h, "omp_set_max_active_levels"));
			// Keep the handle: the library stays loaded by Tesseract anyway.
			if (f)
				break;
		}
		return f;
	}();
	thread_local bool done = false;
	if (fn && !done) {
		fn(0);
		done = true;
	}
#endif
}

class TesseractEngine : public OcrEngine {
	static constexpr int kDeadlineMs = 400;

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
		// We normalise light-on-dark regions ourselves (normalize_polarity),
		// so skip Tesseract's per-line "try it inverted" pass.
		api_.SetVariable("tessedit_do_invert", "0");
		return true;
	}

	const char *name() const override { return "Tesseract"; }

	std::vector<OcrLine> recognize(const Image &bgra) override
	{
		disable_openmp_parallelism();
		std::vector<OcrLine> lines;
		Image grey = to_grey(bgra);
		normalize_polarity(grey);
		if (grey.empty())
			return lines;

		api_.SetImage(grey.pixels.data(), static_cast<int>(grey.width), static_cast<int>(grey.height), 1,
			      static_cast<int>(grey.stride()));
		api_.SetSourceResolution(96);
		// Tesseract occasionally spends seconds on cut-off glyphs or noise;
		// cap each band so one bad region cannot stall the whole scan.
		tesseract::ETEXT_DESC monitor;
		monitor.set_deadline_msecs(kDeadlineMs);
		if (api_.Recognize(&monitor) != 0 && !monitor.deadline_exceeded())
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
	disable_openmp_parallelism();
	auto engine = std::make_unique<TesseractEngine>();
	if (!engine->init(config, error))
		return nullptr;
	return engine;
}

} // namespace pii
