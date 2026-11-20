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

// Windows.Media.Ocr backend (Windows 10+, no extra dependencies). Uses the
// OCR languages installed with Windows (Settings > Time & language >
// Language > Optional features).

#include "ocr-engine.hpp"

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Globalization.h>
#include <winrt/Windows.Graphics.Imaging.h>
#include <winrt/Windows.Media.Ocr.h>
#include <winrt/Windows.Storage.Streams.h>

#include <algorithm>
#include <cmath>
#include <cstring>

namespace pii {

namespace {

namespace wf = winrt::Windows::Foundation;
namespace wg = winrt::Windows::Globalization;
namespace wi = winrt::Windows::Graphics::Imaging;
namespace wo = winrt::Windows::Media::Ocr;
namespace ws = winrt::Windows::Storage::Streams;

class WindowsOcrEngine : public OcrEngine {
public:
	bool init(const OcrConfig &config, std::string &error)
	{
		try {
			// The analysis thread is ours; make it an MTA so .get() is allowed.
			winrt::init_apartment(winrt::apartment_type::multi_threaded);
		} catch (const winrt::hresult_error &) {
			// Already initialised (possibly as STA by someone else); carry on.
		}

		try {
			if (!config.language.empty()) {
				wg::Language lang{winrt::to_hstring(config.language)};
				if (wo::OcrEngine::IsLanguageSupported(lang))
					engine_ = wo::OcrEngine::TryCreateFromLanguage(lang);
			}
			if (!engine_)
				engine_ = wo::OcrEngine::TryCreateFromUserProfileLanguages();
		} catch (const winrt::hresult_error &e) {
			error = "Windows OCR init failed: " + winrt::to_string(e.message());
			return false;
		}

		if (!engine_) {
			error = "Windows OCR: no OCR language pack is installed for the user profile languages";
			return false;
		}
		max_dim_ = wo::OcrEngine::MaxImageDimension();
		return true;
	}

	const char *name() const override { return "Windows.Media.Ocr"; }

	std::vector<OcrLine> recognize(const Image &input) override
	{
		std::vector<OcrLine> lines;
		if (input.empty() || input.channels != 4)
			return lines;

		// Windows OCR refuses images larger than MaxImageDimension.
		const Image *img = &input;
		Image scaled;
		double scale = 1.0;
		const uint32_t longest = std::max(input.width, input.height);
		if (max_dim_ > 0 && longest > max_dim_) {
			scale = static_cast<double>(max_dim_) / longest;
			const uint32_t w = std::max<uint32_t>(1, static_cast<uint32_t>(input.width * scale));
			const uint32_t h = std::max<uint32_t>(1, static_cast<uint32_t>(input.height * scale));
			scaled = resize(input, w, h);
			img = &scaled;
		}

		try {
			const uint32_t size = static_cast<uint32_t>(img->pixels.size());
			ws::Buffer buffer(size);
			std::memcpy(buffer.data(), img->pixels.data(), size);
			buffer.Length(size);

			wi::SoftwareBitmap bitmap(wi::BitmapPixelFormat::Bgra8, static_cast<int32_t>(img->width),
						  static_cast<int32_t>(img->height), wi::BitmapAlphaMode::Ignore);
			bitmap.CopyFromBuffer(buffer);

			wo::OcrResult result = engine_.RecognizeAsync(bitmap).get();
			const double inv = 1.0 / scale;
			for (const wo::OcrLine &line : result.Lines()) {
				OcrLine out;
				for (const wo::OcrWord &word : line.Words()) {
					const wf::Rect r = word.BoundingRect();
					OcrWord w;
					w.text = winrt::to_string(word.Text());
					const int x0 = static_cast<int>(std::floor(r.X * inv));
					const int y0 = static_cast<int>(std::floor(r.Y * inv));
					const int x1 = static_cast<int>(std::ceil((r.X + r.Width) * inv));
					const int y1 = static_cast<int>(std::ceil((r.Y + r.Height) * inv));
					w.box = {x0, y0, x1 - x0, y1 - y0};
					out.words.push_back(std::move(w));
				}
				if (!out.words.empty())
					lines.push_back(std::move(out));
			}
		} catch (const winrt::hresult_error &) {
			lines.clear();
		}
		return lines;
	}

private:
	wo::OcrEngine engine_{nullptr};
	uint32_t max_dim_ = 0;
};

} // namespace

std::unique_ptr<OcrEngine> create_windows_ocr_engine(const OcrConfig &config, std::string &error)
{
	auto engine = std::make_unique<WindowsOcrEngine>();
	if (!engine->init(config, error))
		return nullptr;
	return engine;
}

} // namespace pii
