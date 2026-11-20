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

// Plain data types shared by the OCR backends, the PII matcher and the
// OBS filter. Nothing in src/core depends on libobs so it can be unit tested
// stand-alone (see tests/).

#include <cstdint>
#include <string>
#include <vector>

namespace pii {

// Axis-aligned rectangle in source pixel coordinates (origin top-left).
struct Rect {
	int x = 0;
	int y = 0;
	int w = 0;
	int h = 0;

	int right() const { return x + w; }
	int bottom() const { return y + h; }
	bool empty() const { return w <= 0 || h <= 0; }

	bool intersects(const Rect &o) const
	{
		return x < o.right() && o.x < right() && y < o.bottom() && o.y < bottom();
	}

	Rect united(const Rect &o) const;
	Rect padded(int pad) const;
	Rect clipped(int width, int height) const;
	Rect scaled(double sx, double sy) const;

	bool operator==(const Rect &o) const { return x == o.x && y == o.y && w == o.w && h == o.h; }
};

// One word as reported by an OCR engine.
struct OcrWord {
	std::string text; // UTF-8
	Rect box;
	float confidence = 100.0f; // 0..100, engines without confidence report 100
};

// A line of words in reading order. The matcher joins words with a single
// space and maps regex matches back onto the word boxes.
struct OcrLine {
	std::vector<OcrWord> words;
};

enum class PiiKind {
	Email,
	Phone,
	Ssn,
	CreditCard,
	IpAddress,
	StreetAddress,
	DateOfBirth,
	Secret,      // API keys, stream keys, tokens
	Keyword,     // user supplied literal
	CustomRegex, // user supplied pattern
};

const char *pii_kind_name(PiiKind kind);

// Merge overlapping (or touching) rectangles until none overlap.
std::vector<Rect> merge_rects(std::vector<Rect> rects);

// Intersection-over-union of two rectangles (0 when disjoint).
double iou(const Rect &a, const Rect &b);

struct Detection {
	PiiKind kind;
	std::string text; // matched text (never logged by default)
	Rect box;         // union of the word boxes covering the match
};

} // namespace pii
