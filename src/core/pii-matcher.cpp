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

#include "pii-matcher.hpp"

#include <algorithm>
#include <cctype>

namespace pii {

namespace {

bool is_digit(char c)
{
	return c >= '0' && c <= '9';
}

bool is_alnum(char c)
{
	return std::isalnum(static_cast<unsigned char>(c)) != 0;
}

std::string ascii_lower(const std::string &s)
{
	std::string out = s;
	for (char &c : out)
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	return out;
}

size_t count_digits(const std::string &s)
{
	return static_cast<size_t>(std::count_if(s.begin(), s.end(), is_digit));
}

using Validator = bool (*)(const std::string &);

bool phone_valid(const std::string &s)
{
	const size_t n = count_digits(s);
	return n >= 10 && n <= 15;
}

bool card_valid(const std::string &s)
{
	const size_t n = count_digits(s);
	return n >= 13 && n <= 19 && luhn_valid(s);
}

bool ipv6_valid(const std::string &s)
{
	const size_t colons = static_cast<size_t>(std::count(s.begin(), s.end(), ':'));
	return colons == 7 || (s.find("::") != std::string::npos && colons >= 2);
}

enum class Boundary {
	None,
	NoAdjacentDigit, // char before/after the match must not be a digit
	NoAdjacentAlnum, // char before/after the match must not be alphanumeric
};

} // namespace

struct PiiMatcher::Rule {
	PiiKind kind;
	std::regex re;
	bool use_normalized; // run on the digit-normalised copy of the line
	Boundary boundary;
	Validator validator;
};

const char *pii_kind_name(PiiKind kind)
{
	switch (kind) {
	case PiiKind::Email:
		return "email";
	case PiiKind::Phone:
		return "phone";
	case PiiKind::Ssn:
		return "ssn";
	case PiiKind::CreditCard:
		return "credit-card";
	case PiiKind::IpAddress:
		return "ip-address";
	case PiiKind::StreetAddress:
		return "street-address";
	case PiiKind::DateOfBirth:
		return "date-of-birth";
	case PiiKind::Secret:
		return "secret";
	case PiiKind::Keyword:
		return "keyword";
	case PiiKind::CustomRegex:
		return "custom";
	}
	return "unknown";
}

bool luhn_valid(const std::string &text)
{
	int sum = 0;
	int n = 0;
	bool dbl = false;
	for (auto it = text.rbegin(); it != text.rend(); ++it) {
		if (!is_digit(*it))
			continue;
		int d = *it - '0';
		if (dbl) {
			d *= 2;
			if (d > 9)
				d -= 9;
		}
		sum += d;
		dbl = !dbl;
		n++;
	}
	return n > 0 && sum % 10 == 0;
}

bool ssn_valid(const std::string &text)
{
	std::string d;
	for (char c : text)
		if (is_digit(c))
			d.push_back(c);
	if (d.size() != 9)
		return false;
	const std::string area = d.substr(0, 3);
	const std::string group = d.substr(3, 2);
	const std::string serial = d.substr(5, 4);
	if (area == "000" || area == "666" || area[0] == '9')
		return false;
	if (group == "00" || serial == "0000")
		return false;
	return true;
}

bool ipv4_valid(const std::string &text)
{
	int parts = 0;
	int value = -1;
	for (char c : text) {
		if (is_digit(c)) {
			value = (value < 0 ? 0 : value * 10) + (c - '0');
			if (value > 255)
				return false;
		} else if (c == '.') {
			if (value < 0)
				return false;
			parts++;
			value = -1;
		} else {
			return false;
		}
	}
	if (value < 0)
		return false;
	parts++;
	return parts == 4;
}

std::string normalize_digits(const std::string &text)
{
	std::string out = text;
	const size_t n = out.size();
	auto map_char = [](char c) -> char {
		switch (c) {
		case 'O':
		case 'o':
		case 'Q':
		case 'D':
			return '0';
		case 'l':
		case 'I':
		case 'i':
		case '|':
		case '!':
			return '1';
		case 'S':
		case 's':
			return '5';
		case 'B':
			return '8';
		case 'Z':
		case 'z':
			return '2';
		default:
			return c;
		}
	};
	for (size_t i = 0; i < n; i++) {
		const char mapped = map_char(out[i]);
		if (mapped == out[i])
			continue;
		const bool prev_digit = i > 0 && is_digit(out[i - 1]);
		const bool next_digit = i + 1 < n && is_digit(text[i + 1]);
		if (prev_digit || next_digit)
			out[i] = mapped;
	}
	return out;
}

PiiMatcher::PiiMatcher(const MatcherConfig &config) : min_confidence_(config.min_confidence)
{
	using std::regex_constants::ECMAScript;
	using std::regex_constants::icase;
	using std::regex_constants::optimize;
	const auto CI = ECMAScript | icase | optimize;
	const auto CS = ECMAScript | optimize;

	auto add = [this](PiiKind kind, const char *pattern, std::regex_constants::syntax_option_type flags,
			  bool normalized, Boundary boundary, Validator validator) {
		rules_.push_back(std::unique_ptr<Rule>(
			new Rule{kind, std::regex(pattern, flags), normalized, boundary, validator}));
	};

	if (config.email) {
		// Tolerates the stray spaces OCR likes to put around '@' and '.'.
		add(PiiKind::Email, R"([a-z0-9._%+-]+ ?@ ?[a-z0-9-]+(?: ?\. ?[a-z0-9-]+)*(?: ?\. ?[a-z]{2,}))", CI,
		    false, Boundary::None, nullptr);
	}

	if (config.phone) {
		// North American style, optional country code.
		add(PiiKind::Phone, R"((?:\+?\d{1,3}[\s.-]?)?(?:\(\s?\d{3}\s?\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4})", CS,
		    true, Boundary::NoAdjacentDigit, phone_valid);
		// International E.164-ish: +CC followed by groups of digits.
		add(PiiKind::Phone, R"(\+\d{1,3}(?:[\s.-]?\(?\d{1,4}\)?){2,6})", CS, true, Boundary::NoAdjacentDigit,
		    phone_valid);
	}

	if (config.ssn) {
		add(PiiKind::Ssn, R"(\d{3}[- ]\d{2}[- ]\d{4})", CS, true, Boundary::NoAdjacentDigit, ssn_valid);
		add(PiiKind::Ssn, R"((?:ssn|social security(?: number| no\.?)?|soc\.? ?sec\.?)[\s:#.-]*\d{9})", CI,
		    true, Boundary::NoAdjacentDigit, nullptr);
	}

	if (config.credit_card) {
		add(PiiKind::CreditCard, R"((?:\d[ -]?){12,18}\d)", CS, true, Boundary::NoAdjacentDigit, card_valid);
	}

	if (config.ip_address) {
		add(PiiKind::IpAddress, R"((?:\d{1,3}\.){3}\d{1,3})", CS, true, Boundary::NoAdjacentDigit, ipv4_valid);
		add(PiiKind::IpAddress, R"([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})", CI, false, Boundary::NoAdjacentAlnum,
		    ipv6_valid);
	}

	if (config.street_address) {
		add(PiiKind::StreetAddress,
		    R"(\d{1,6}(?:\s+[a-z0-9.'-]+){1,5}?\s+(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|way|place|pl|terrace|ter|circle|cir|highway|hwy|parkway|pkwy|square|sq|trail|trl|crescent|cres|alley|aly)\b\.?(?:,?\s*(?:apt|apartment|suite|ste|unit|#)\.?\s*#?\s*[a-z0-9-]+)?)",
		    CI, false, Boundary::NoAdjacentAlnum, nullptr);
		add(PiiKind::StreetAddress, R"(p\.?\s?o\.?\s+box\s+\d+)", CI, false, Boundary::NoAdjacentAlnum,
		    nullptr);
		// "Tucson, Arizona 85705" (full state name).
		add(PiiKind::StreetAddress,
		    R"([A-Z][A-Za-z.' -]{1,30},\s*(?:Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming|District of Columbia)\s+\d{5}(?:-\d{4})?)",
		    CS, false, Boundary::NoAdjacentAlnum, nullptr);
		// "Springfield, IL 62704" / "Springfield, IL 62704-1234" (case sensitive on purpose).
		add(PiiKind::StreetAddress, R"([A-Z][A-Za-z.' -]{1,30},\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)", CS, false,
		    Boundary::NoAdjacentAlnum, nullptr);
	}

	if (config.date_of_birth) {
		add(PiiKind::DateOfBirth,
		    R"((?:dob|d\.o\.b\.?|date of birth|birth ?date|born(?: on)?)[\s:]*\d{1,4}[/. -]\d{1,2}[/. -]\d{1,4})",
		    CI, true, Boundary::NoAdjacentDigit, nullptr);
		add(PiiKind::DateOfBirth,
		    R"((?:dob|d\.o\.b\.?|date of birth|birth ?date|born(?: on)?)[\s:]*(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})",
		    CI, true, Boundary::NoAdjacentDigit, nullptr);
	}

	if (config.secrets) {
		const Boundary B = Boundary::NoAdjacentAlnum;
		add(PiiKind::Secret, R"((?:AKIA|ASIA)[0-9A-Z]{16})", CS, false, B, nullptr);  // AWS
		add(PiiKind::Secret, R"(gh[pousr]_[A-Za-z0-9]{30,})", CS, false, B, nullptr); // GitHub
		add(PiiKind::Secret, R"(github_pat_[A-Za-z0-9_]{40,})", CS, false, B, nullptr);
		add(PiiKind::Secret, R"(xox[abposr]-[A-Za-z0-9-]{10,})", CS, false, B, nullptr); // Slack
		add(PiiKind::Secret, R"(AIza[0-9A-Za-z_-]{35})", CS, false, B, nullptr);         // Google
		add(PiiKind::Secret, R"((?:sk|pk|rk)[-_](?:live|test|proj|ant)?[-_]?[A-Za-z0-9_-]{20,})", CS, false, B,
		    nullptr); // Stripe / OpenAI / Anthropic style
		add(PiiKind::Secret, R"(live_\d{5,}_[A-Za-z0-9]{20,})", CS, false, B, nullptr); // Twitch stream key
		add(PiiKind::Secret, R"([a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", CS, false, B,
		    nullptr); // YouTube stream key
		add(PiiKind::Secret, R"(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})", CS, false, B,
		    nullptr); // JWT
		add(PiiKind::Secret, R"(-----BEGIN [A-Z ]*PRIVATE KEY-----)", CS, false, Boundary::None, nullptr);
		add(PiiKind::Secret,
		    R"((?:password|passwd|pwd|api[_ -]?key|secret|access[_ -]?token|auth[_ -]?token|stream[_ -]?key)\s*[:=]\s*\S{4,})",
		    CI, false, Boundary::None, nullptr);
	}

	for (const std::string &kw : config.keywords) {
		if (!kw.empty())
			keywords_lower_.push_back(ascii_lower(kw));
	}

	for (const std::string &pattern : config.custom_patterns) {
		if (pattern.empty())
			continue;
		try {
			rules_.push_back(std::unique_ptr<Rule>(new Rule{PiiKind::CustomRegex, std::regex(pattern, CI),
									false, Boundary::None, nullptr}));
		} catch (const std::regex_error &) {
			invalid_patterns_.push_back(pattern);
		}
	}
}

PiiMatcher::~PiiMatcher() = default;

std::vector<PiiMatcher::Span> PiiMatcher::match_text(const std::string &text) const
{
	std::vector<Span> spans;
	if (text.empty())
		return spans;

	const std::string normalized = normalize_digits(text);

	for (const auto &rule : rules_) {
		const std::string &subject = rule->use_normalized ? normalized : text;
		auto begin = std::sregex_iterator(subject.begin(), subject.end(), rule->re);
		for (auto it = begin; it != std::sregex_iterator(); ++it) {
			const std::smatch &m = *it;
			if (m.length(0) == 0)
				continue;
			const size_t start = static_cast<size_t>(m.position(0));
			const size_t end = start + static_cast<size_t>(m.length(0));

			if (rule->boundary != Boundary::None) {
				auto bad = [&](char c) {
					return rule->boundary == Boundary::NoAdjacentDigit ? is_digit(c) : is_alnum(c);
				};
				if (start > 0 && bad(subject[start - 1]))
					continue;
				if (end < subject.size() && bad(subject[end]))
					continue;
			}

			if (rule->validator && !rule->validator(m.str(0)))
				continue;

			spans.push_back({rule->kind, start, end});
		}
	}

	if (!keywords_lower_.empty()) {
		const std::string lower = ascii_lower(text);
		for (const std::string &kw : keywords_lower_) {
			size_t pos = lower.find(kw);
			while (pos != std::string::npos) {
				spans.push_back({PiiKind::Keyword, pos, pos + kw.size()});
				pos = lower.find(kw, pos + kw.size());
			}
		}
	}

	return spans;
}

std::vector<Detection> PiiMatcher::match(const std::vector<OcrLine> &lines) const
{
	std::vector<Detection> detections;

	for (const OcrLine &line : lines) {
		if (line.words.empty())
			continue;

		// Join words with single spaces, remembering each word's byte span.
		std::string text;
		std::vector<std::pair<size_t, size_t>> word_spans;
		word_spans.reserve(line.words.size());
		for (const OcrWord &w : line.words) {
			if (!text.empty())
				text.push_back(' ');
			const size_t s = text.size();
			text += w.text;
			word_spans.emplace_back(s, text.size());
		}

		for (const Span &span : match_text(text)) {
			Rect box;
			bool have_box = false;
			bool confident = min_confidence_ <= 0.0f;
			for (size_t i = 0; i < line.words.size(); i++) {
				const auto &ws = word_spans[i];
				if (ws.first >= span.end || ws.second <= span.start)
					continue;
				const OcrWord &w = line.words[i];
				if (w.box.empty())
					continue;
				box = have_box ? box.united(w.box) : w.box;
				have_box = true;
				if (w.confidence >= min_confidence_)
					confident = true;
			}
			if (!have_box || !confident)
				continue;
			detections.push_back({span.kind, text.substr(span.start, span.end - span.start), box});
		}
	}

	return detections;
}

} // namespace pii
