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

#include "pii-types.hpp"

#include <algorithm>
#include <cmath>

namespace pii {

Rect Rect::united(const Rect &o) const
{
	if (empty())
		return o;
	if (o.empty())
		return *this;
	const int l = std::min(x, o.x);
	const int t = std::min(y, o.y);
	const int r = std::max(right(), o.right());
	const int b = std::max(bottom(), o.bottom());
	return {l, t, r - l, b - t};
}

Rect Rect::padded(int pad) const
{
	return {x - pad, y - pad, w + 2 * pad, h + 2 * pad};
}

Rect Rect::clipped(int width, int height) const
{
	const int l = std::max(0, x);
	const int t = std::max(0, y);
	const int r = std::min(width, right());
	const int b = std::min(height, bottom());
	if (r <= l || b <= t)
		return {};
	return {l, t, r - l, b - t};
}

Rect Rect::scaled(double sx, double sy) const
{
	// Round outwards so scaling never shrinks the covered area.
	const int l = static_cast<int>(std::floor(x * sx));
	const int t = static_cast<int>(std::floor(y * sy));
	const int r = static_cast<int>(std::ceil(right() * sx));
	const int b = static_cast<int>(std::ceil(bottom() * sy));
	return {l, t, r - l, b - t};
}

std::vector<Rect> merge_rects(std::vector<Rect> rects)
{
	rects.erase(std::remove_if(rects.begin(), rects.end(), [](const Rect &r) { return r.empty(); }), rects.end());

	bool merged = true;
	while (merged) {
		merged = false;
		for (size_t i = 0; i < rects.size() && !merged; i++) {
			for (size_t j = i + 1; j < rects.size(); j++) {
				if (rects[i].padded(1).intersects(rects[j])) {
					rects[i] = rects[i].united(rects[j]);
					rects.erase(rects.begin() + static_cast<std::ptrdiff_t>(j));
					merged = true;
					break;
				}
			}
		}
	}
	return rects;
}

double iou(const Rect &a, const Rect &b)
{
	const int l = std::max(a.x, b.x);
	const int t = std::max(a.y, b.y);
	const int r = std::min(a.right(), b.right());
	const int btm = std::min(a.bottom(), b.bottom());
	if (r <= l || btm <= t)
		return 0.0;
	const double inter = static_cast<double>(r - l) * (btm - t);
	const double uni = static_cast<double>(a.w) * a.h + static_cast<double>(b.w) * b.h - inter;
	return uni > 0 ? inter / uni : 0.0;
}

} // namespace pii
