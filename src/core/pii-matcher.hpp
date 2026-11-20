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

#include "pii-types.hpp"

#include <memory>
#include <regex>
#include <string>
#include <vector>

namespace pii {

struct MatcherConfig {
	bool email = true;
	bool phone = true;
	bool ssn = true;
	bool credit_card = true;
	bool ip_address = false;
	bool street_address = true;
	bool date_of_birth = true;
	bool secrets = true;

	// Literal strings to always redact (case-insensitive), e.g. your real
	// name, street or employer. One entry per element.
	std::vector<std::string> keywords;
	// Extra ECMAScript regular expressions (case-insensitive).
	std::vector<std::string> custom_patterns;

	// Words below this OCR confidence are ignored when they would be the
	// only evidence for a match. 0 disables the check.
	float min_confidence = 0.0f;
};

// Finds PII inside OCR output and maps it back to screen rectangles.
//
// Matching happens per line on the words joined by single spaces. For the
// numeric detectors a second, "digit-normalised" copy of the line is used in
// which common OCR confusions (O->0, l/I/|->1, S->5, B->8) are fixed when the
// character sits next to a digit; the copy has identical byte offsets so
// matches still map onto the right words.
class PiiMatcher {
public:
	explicit PiiMatcher(const MatcherConfig &config);
	~PiiMatcher();

	PiiMatcher(const PiiMatcher &) = delete;
	PiiMatcher &operator=(const PiiMatcher &) = delete;

	std::vector<Detection> match(const std::vector<OcrLine> &lines) const;

	// Convenience for tests / non-OCR callers: match a single string and
	// return [start, end) byte ranges with their kind.
	struct Span {
		PiiKind kind;
		size_t start;
		size_t end;
	};
	std::vector<Span> match_text(const std::string &text) const;

	// Patterns that failed to compile (reported to the user via the log).
	const std::vector<std::string> &invalid_patterns() const { return invalid_patterns_; }

private:
	struct Rule;
	std::vector<std::unique_ptr<Rule>> rules_;
	std::vector<std::string> keywords_lower_;
	std::vector<std::string> invalid_patterns_;
	float min_confidence_ = 0.0f;
};

// Validators, exposed for unit tests.
bool luhn_valid(const std::string &digits_and_separators);
bool ssn_valid(const std::string &text);
bool ipv4_valid(const std::string &text);
std::string normalize_digits(const std::string &text);

} // namespace pii
