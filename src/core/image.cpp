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

#include "image.hpp"

#include <algorithm>
#include <cstring>

namespace pii {

Image image_from_bgra(const uint8_t *data, uint32_t width, uint32_t height, uint32_t linesize)
{
	Image img;
	img.width = width;
	img.height = height;
	img.channels = 4;
	img.pixels.resize(static_cast<size_t>(width) * height * 4);
	const size_t row = static_cast<size_t>(width) * 4;
	for (uint32_t y = 0; y < height; y++)
		std::memcpy(img.pixels.data() + y * row, data + static_cast<size_t>(y) * linesize, row);
	return img;
}

Image image_from_grey(const uint8_t *data, uint32_t width, uint32_t height, uint32_t linesize)
{
	Image img;
	img.width = width;
	img.height = height;
	img.channels = 1;
	img.pixels.resize(static_cast<size_t>(width) * height);
	for (uint32_t y = 0; y < height; y++)
		std::memcpy(img.pixels.data() + static_cast<size_t>(y) * width,
			    data + static_cast<size_t>(y) * linesize, width);
	return img;
}

Image resize(const Image &src, uint32_t width, uint32_t height)
{
	if (src.empty() || width == 0 || height == 0)
		return {};
	if (width == src.width && height == src.height)
		return src;

	Image dst;
	dst.width = width;
	dst.height = height;
	dst.channels = src.channels;
	dst.pixels.resize(static_cast<size_t>(width) * height * src.channels);

	const uint32_t ch = src.channels;
	for (uint32_t y = 0; y < height; y++) {
		const uint32_t sy0 = static_cast<uint32_t>(static_cast<uint64_t>(y) * src.height / height);
		uint32_t sy1 = static_cast<uint32_t>(static_cast<uint64_t>(y + 1) * src.height / height);
		sy1 = std::max(sy1, sy0 + 1);
		for (uint32_t x = 0; x < width; x++) {
			const uint32_t sx0 = static_cast<uint32_t>(static_cast<uint64_t>(x) * src.width / width);
			uint32_t sx1 = static_cast<uint32_t>(static_cast<uint64_t>(x + 1) * src.width / width);
			sx1 = std::max(sx1, sx0 + 1);
			const uint32_t count = (sx1 - sx0) * (sy1 - sy0);
			for (uint32_t c = 0; c < ch; c++) {
				uint32_t sum = 0;
				for (uint32_t sy = sy0; sy < sy1; sy++) {
					const uint8_t *row = src.pixels.data() + static_cast<size_t>(sy) * src.stride();
					for (uint32_t sx = sx0; sx < sx1; sx++)
						sum += row[sx * ch + c];
				}
				dst.pixels[(static_cast<size_t>(y) * width + x) * ch + c] =
					static_cast<uint8_t>(sum / count);
			}
		}
	}
	return dst;
}

Image to_grey(const Image &bgra)
{
	Image g;
	if (bgra.empty())
		return g;
	if (bgra.channels == 1)
		return bgra;
	g.width = bgra.width;
	g.height = bgra.height;
	g.channels = 1;
	g.pixels.resize(static_cast<size_t>(g.width) * g.height);
	const size_t n = g.pixels.size();
	const uint8_t *p = bgra.pixels.data();
	for (size_t i = 0; i < n; i++, p += 4) {
		const uint32_t b = p[0], gg = p[1], r = p[2];
		g.pixels[i] = static_cast<uint8_t>((r * 77 + gg * 150 + b * 29) >> 8);
	}
	return g;
}

void normalize_polarity(Image &grey, int tile)
{
	if (grey.empty() || grey.channels != 1 || tile <= 0)
		return;
	const int w = static_cast<int>(grey.width);
	const int h = static_cast<int>(grey.height);
	for (int ty = 0; ty < h; ty += tile) {
		for (int tx = 0; tx < w; tx += tile) {
			const int x1 = std::min(w, tx + tile);
			const int y1 = std::min(h, ty + tile);
			uint64_t sum = 0;
			for (int y = ty; y < y1; y++) {
				const uint8_t *row = grey.pixels.data() + static_cast<size_t>(y) * w;
				for (int x = tx; x < x1; x++)
					sum += row[x];
			}
			const uint64_t n = static_cast<uint64_t>(x1 - tx) * static_cast<uint64_t>(y1 - ty);
			if (sum >= n * 110)
				continue; // light enough: text is presumably dark-on-light
			for (int y = ty; y < y1; y++) {
				uint8_t *row = grey.pixels.data() + static_cast<size_t>(y) * w;
				for (int x = tx; x < x1; x++)
					row[x] = static_cast<uint8_t>(255 - row[x]);
			}
		}
	}
}

} // namespace pii
