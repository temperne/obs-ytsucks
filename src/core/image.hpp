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

#include <cstdint>
#include <vector>

namespace pii {

// Tightly packed 8-bit-per-channel image owned by the analysis thread.
struct Image {
	uint32_t width = 0;
	uint32_t height = 0;
	uint32_t channels = 4; // 4 = BGRA, 1 = grey
	std::vector<uint8_t> pixels;

	uint32_t stride() const { return width * channels; }
	bool empty() const { return width == 0 || height == 0 || pixels.empty(); }
};

// Copy a (possibly padded) BGRA buffer into a packed Image.
Image image_from_bgra(const uint8_t *data, uint32_t width, uint32_t height, uint32_t linesize);

// Copy a (possibly padded) 8-bit single-channel buffer into a packed Image.
Image image_from_grey(const uint8_t *data, uint32_t width, uint32_t height, uint32_t linesize);

// Area-average resample to the given size (any channel count).
Image resize(const Image &src, uint32_t width, uint32_t height);

// BGRA -> 8-bit luma (BT.601).
Image to_grey(const Image &bgra);

// Make all text dark-on-light: every `tile` x `tile` block whose mean is
// dark (a dark-mode window, a terminal...) is inverted in place. Lets OCR
// skip its own "try the line inverted too" pass, which costs ~30-40%.
void normalize_polarity(Image &grey, int tile = 48);

} // namespace pii
