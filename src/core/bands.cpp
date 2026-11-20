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

#include "bands.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>

namespace pii {

std::vector<Band> plan_bands(int height, int count, int overlap, int min_height)
{
	std::vector<Band> bands;
	if (height <= 0)
		return bands;
	count = std::max(1, count);
	overlap = std::max(0, overlap);
	min_height = std::max(1, min_height);

	// Reduce the count until each band is at least min_height tall.
	while (count > 1) {
		const int core = (height + count - 1) / count;
		if (core + overlap >= min_height)
			break;
		count--;
	}
	if (count == 1) {
		bands.push_back({0, height});
		return bands;
	}

	const int core = (height + count - 1) / count;
	for (int i = 0; i < count; i++) {
		int y0 = i * core - overlap / 2;
		int y1 = (i + 1) * core + (overlap - overlap / 2);
		y0 = std::max(0, y0);
		y1 = std::min(height, y1);
		if (y1 > y0)
			bands.push_back({y0, y1 - y0});
	}
	return bands;
}

Image crop(const Image &src, const Rect &r_in)
{
	const Rect r = r_in.clipped(static_cast<int>(src.width), static_cast<int>(src.height));
	Image out;
	if (r.empty() || src.empty())
		return out;
	out.width = static_cast<uint32_t>(r.w);
	out.height = static_cast<uint32_t>(r.h);
	out.channels = src.channels;
	out.pixels.resize(static_cast<size_t>(out.stride()) * out.height);
	const size_t row = out.stride();
	for (int y = 0; y < r.h; y++) {
		const uint8_t *s = src.pixels.data() + static_cast<size_t>(r.y + y) * src.stride() +
				   static_cast<size_t>(r.x) * src.channels;
		std::memcpy(out.pixels.data() + static_cast<size_t>(y) * row, s, row);
	}
	return out;
}

double mean_abs_diff(const Image &a, const Image &b, int step)
{
	if (a.width != b.width || a.height != b.height || a.channels != b.channels || a.empty())
		return 1e9;
	step = std::max(1, step);
	uint64_t sum = 0;
	uint64_t n = 0;
	const uint32_t ch = a.channels;
	for (uint32_t y = 0; y < a.height; y += static_cast<uint32_t>(step)) {
		const uint8_t *ra = a.pixels.data() + static_cast<size_t>(y) * a.stride();
		const uint8_t *rb = b.pixels.data() + static_cast<size_t>(y) * b.stride();
		for (uint32_t x = 0; x < a.width; x += static_cast<uint32_t>(step)) {
			for (uint32_t c = 0; c < ch; c++) {
				sum += static_cast<uint64_t>(
					std::abs(static_cast<int>(ra[x * ch + c]) - static_cast<int>(rb[x * ch + c])));
				n++;
			}
		}
	}
	return n ? static_cast<double>(sum) / static_cast<double>(n) : 0.0;
}

int estimate_vertical_shift(const Image &prev, const Image &cur, int max_shift, int x0, int x1)
{
	if (prev.width != cur.width || prev.height != cur.height || prev.channels != 1 || cur.channels != 1 ||
	    cur.empty())
		return 0;
	const int h = static_cast<int>(cur.height);
	if (x1 < 0 || x1 > static_cast<int>(cur.width))
		x1 = static_cast<int>(cur.width);
	x0 = std::max(0, x0);
	if (x1 <= x0)
		return 0;
	const int w = x1 - x0;
	auto profile = [&](const Image &img) {
		std::vector<double> p(static_cast<size_t>(h));
		for (int y = 0; y < h; y++) {
			uint64_t sum = 0;
			const uint8_t *row = img.pixels.data() + static_cast<size_t>(y) * img.width;
			for (int x = x0; x < x1; x++)
				sum += row[x];
			p[static_cast<size_t>(y)] = static_cast<double>(sum) / w;
		}
		return p;
	};
	const std::vector<double> pp = profile(prev), pc = profile(cur);
	max_shift = std::min(max_shift, h / 2);

	int best = 0;
	double best_cost = 1e18;
	for (int s = -max_shift; s <= max_shift; s++) {
		double sum = 0;
		int n = 0;
		for (int y = std::max(0, s); y < std::min(h, h + s); y++) {
			sum += std::fabs(pc[static_cast<size_t>(y)] - pp[static_cast<size_t>(y - s)]);
			n++;
		}
		if (n * 2 < h)
			continue;
		const double cost = sum / n + 0.001 * std::abs(s); // prefer small shifts on ties
		if (cost < best_cost) {
			best_cost = cost;
			best = s;
		}
	}
	return best;
}

double shifted_band_diff(const Image &prev, const Image &cur, int y0, int y1, int shift, double &new_fraction, int x0,
			 int x1)
{
	new_fraction = 1.0;
	if (prev.width != cur.width || prev.height != cur.height || prev.channels != 1 || cur.channels != 1)
		return 1e9;
	const int h = static_cast<int>(cur.height);
	y0 = std::max(0, y0);
	y1 = std::min(h, y1);
	if (y1 <= y0)
		return 1e9;
	if (x1 < 0 || x1 > static_cast<int>(cur.width))
		x1 = static_cast<int>(cur.width);
	x0 = std::max(0, x0);
	if (x1 <= x0)
		return 1e9;
	uint64_t sum = 0, n = 0;
	int new_rows = 0;
	for (int y = y0; y < y1; y++) {
		const int py = y - shift;
		if (py < 0 || py >= h) {
			new_rows++;
			continue;
		}
		const uint8_t *rc = cur.pixels.data() + static_cast<size_t>(y) * cur.width;
		const uint8_t *rp = prev.pixels.data() + static_cast<size_t>(py) * prev.width;
		for (int x = x0; x < x1; x++)
			sum += static_cast<uint64_t>(std::abs(static_cast<int>(rc[x]) - static_cast<int>(rp[x])));
		n += static_cast<uint64_t>(x1 - x0);
	}
	new_fraction = static_cast<double>(new_rows) / (y1 - y0);
	return n ? static_cast<double>(sum) / static_cast<double>(n) : 1e9;
}

} // namespace pii
