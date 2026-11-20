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

// Splitting a frame into overlapping horizontal bands so OCR can run on
// several threads, plus the cheap change test used to skip bands whose
// content did not change since the last scan.

#include "image.hpp"
#include "pii-types.hpp"

#include <utility>
#include <vector>

namespace pii {

struct Band {
	int y = 0;
	int h = 0;
	bool operator==(const Band &o) const { return y == o.y && h == o.h; }
};

// `count` bands covering [0, height) where consecutive bands overlap by
// `overlap` pixels (so any text line shorter than that is fully inside at
// least one band). Bands are never shorter than `min_height` (fewer bands
// are returned instead).
std::vector<Band> plan_bands(int height, int count, int overlap, int min_height);

// Copy a rectangle out of an image (any channel count). `r` is clipped.
Image crop(const Image &src, const Rect &r);

// Mean absolute difference per byte of two same-sized images (sampling every
// `step`-th pixel in both directions). Returns a large value on size mismatch.
double mean_abs_diff(const Image &a, const Image &b, int step = 1);

// Vertical scroll between two same-sized grey images: the shift s (rows)
// such that cur(y) ~= prev(y - s), searched within +-max_shift using row
// profiles of columns [x0, x1) (x1 < 0 = full width). Positive s = content
// moved down.
int estimate_vertical_shift(const Image &prev, const Image &cur, int max_shift, int x0 = 0, int x1 = -1);

// Mean absolute difference between rows [y0, y1) of `cur` and the same rows
// of `prev` shifted by `shift` (cur(y) vs prev(y - shift)), columns
// [x0, x1) only (x1 < 0 = full width). Rows that come
// from outside `prev` count as "new". `new_fraction` receives the share of
// such rows. Returns a large value on size mismatch.
double shifted_band_diff(const Image &prev, const Image &cur, int y0, int y1, int shift, double &new_fraction,
			 int x0 = 0, int x1 = -1);

// Split rows [y0, y1) of a grey image into horizontal segments at window
// borders (a vertical edge running through most of the rows) and at blank
// vertical gaps at least `min_gap` px wide. OCR'ing each segment separately
// stops text from side-by-side windows being glued into one "line".
// Returns [x0, x1) ranges; blank segments are dropped.
std::vector<std::pair<int, int>> split_columns(const Image &grey, int y0, int y1, int min_gap = 16, int min_width = 24);

} // namespace pii
