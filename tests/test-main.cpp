// Minimal self-contained test runner for src/core (no external framework).
#include "image.hpp"
#include "pii-matcher.hpp"
#include "region-tracker.hpp"

#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

using namespace pii;

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                            \
	do {                                                                   \
		g_checks++;                                                    \
		if (!(cond)) {                                                 \
			g_failures++;                                          \
			std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__,  \
				    #cond);                                    \
		}                                                              \
	} while (0)

static bool has_kind(const PiiMatcher &m, const std::string &text, PiiKind kind)
{
	for (const auto &s : m.match_text(text))
		if (s.kind == kind)
			return true;
	return false;
}

static bool any_match(const PiiMatcher &m, const std::string &text)
{
	return !m.match_text(text).empty();
}

static OcrLine make_line(const std::string &text, int char_w = 10, int h = 20)
{
	OcrLine line;
	std::istringstream ss(text);
	std::string word;
	int x = 0;
	while (ss >> word) {
		OcrWord w;
		w.text = word;
		w.box = {x, 100, static_cast<int>(word.size()) * char_w, h};
		line.words.push_back(w);
		x += static_cast<int>(word.size() + 1) * char_w;
	}
	return line;
}

static void test_validators()
{
	CHECK(luhn_valid("4111 1111 1111 1111"));
	CHECK(luhn_valid("5500-0000-0000-0004"));
	CHECK(!luhn_valid("4111 1111 1111 1112"));
	CHECK(ssn_valid("123-45-6789"));
	CHECK(!ssn_valid("000-12-3456"));
	CHECK(!ssn_valid("666-12-3456"));
	CHECK(!ssn_valid("923-12-3456"));
	CHECK(!ssn_valid("123-00-3456"));
	CHECK(ipv4_valid("192.168.1.20"));
	CHECK(!ipv4_valid("256.1.1.1"));
	CHECK(!ipv4_valid("1.2.3"));
	CHECK(normalize_digits("555-l23-4S67") == "555-123-4567");
	CHECK(normalize_digits("Hello Sam") == "Hello Sam");
	CHECK(normalize_digits("2O24") == "2024");
}

static void test_detectors()
{
	MatcherConfig cfg;
	cfg.ip_address = true;
	PiiMatcher m(cfg);

	CHECK(has_kind(m, "contact john.doe@example.com today", PiiKind::Email));
	CHECK(has_kind(m, "mail: jane_d @ mail.example.co.uk", PiiKind::Email));
	CHECK(has_kind(m, "Call (555) 123-4567 now", PiiKind::Phone));
	CHECK(has_kind(m, "Call 555.123.4567", PiiKind::Phone));
	CHECK(has_kind(m, "+1 555 123 4567", PiiKind::Phone));
	CHECK(has_kind(m, "+44 20 7946 0958", PiiKind::Phone));
	CHECK(has_kind(m, "phone 555-l23-4567", PiiKind::Phone)); // OCR l -> 1
	CHECK(has_kind(m, "SSN 123-45-6789", PiiKind::Ssn));
	CHECK(has_kind(m, "SSN: 123456789", PiiKind::Ssn));
	CHECK(has_kind(m, "card 4111 1111 1111 1111 exp", PiiKind::CreditCard));
	CHECK(!has_kind(m, "card 4111 1111 1111 1112 exp", PiiKind::CreditCard));
	CHECK(has_kind(m, "server 192.168.1.20 down", PiiKind::IpAddress));
	CHECK(has_kind(m, "fe80::1ff:fe23:4567:890a", PiiKind::IpAddress));
	CHECK(has_kind(m, "lives at 1600 Pennsylvania Ave NW", PiiKind::StreetAddress));
	CHECK(has_kind(m, "123 Main Street, Apt 4B", PiiKind::StreetAddress));
	CHECK(has_kind(m, "PO Box 1234", PiiKind::StreetAddress));
	CHECK(has_kind(m, "Springfield, IL 62704", PiiKind::StreetAddress));
	CHECK(has_kind(m, "DOB: 01/02/1990", PiiKind::DateOfBirth));
	CHECK(has_kind(m, "Date of birth March 3, 1985", PiiKind::DateOfBirth));
	CHECK(has_kind(m, "key AKIAIOSFODNN7EXAMPLE", PiiKind::Secret));
	CHECK(has_kind(m, "ghp_abcdefghijklmnopqrstuvwxyz0123456789", PiiKind::Secret));
	CHECK(has_kind(m, "live_123456789_abcdefghijklmnopqrstuvwx", PiiKind::Secret));
	CHECK(has_kind(m, "stream key: abcd-1234-efgh-5678-ij90", PiiKind::Secret));
	CHECK(has_kind(m, "password = hunter22", PiiKind::Secret));

	// Things that must not trigger.
	CHECK(!any_match(m, "The quick brown fox jumps over the lazy dog"));
	CHECK(!any_match(m, "Score 12:30:45 at level 99"));
	CHECK(!any_match(m, "Version 1.2.3 released 2024"));
	CHECK(!any_match(m, "OBS Studio 31.1.1"));
	CHECK(!any_match(m, "Room 404 on floor 3"));
}

static void test_disabled_detectors()
{
	MatcherConfig cfg;
	cfg.email = cfg.phone = cfg.ssn = cfg.credit_card = false;
	cfg.ip_address = cfg.street_address = cfg.date_of_birth = cfg.secrets = false;
	PiiMatcher m(cfg);
	CHECK(!any_match(m, "john.doe@example.com (555) 123-4567 123-45-6789"));
}

static void test_keywords_and_custom()
{
	MatcherConfig cfg;
	cfg.keywords = {"Jane Q Public", "acme corp"};
	cfg.custom_patterns = {"case-\\d{4}", "([unclosed"};
	PiiMatcher m(cfg);
	CHECK(has_kind(m, "hello JANE Q PUBLIC!", PiiKind::Keyword));
	CHECK(has_kind(m, "works at Acme Corp", PiiKind::Keyword));
	CHECK(has_kind(m, "docket CASE-2024 filed", PiiKind::CustomRegex));
	CHECK(m.invalid_patterns().size() == 1);
}

static void test_box_mapping()
{
	MatcherConfig cfg;
	PiiMatcher m(cfg);
	// words: "Call"(0..40) "(555)"(50..100) "123-4567"(110..190) "today"(200..250)
	std::vector<OcrLine> lines = {make_line("Call (555) 123-4567 today")};
	auto d = m.match(lines);
	CHECK(d.size() == 1);
	if (!d.empty()) {
		CHECK(d[0].kind == PiiKind::Phone);
		CHECK(d[0].box.x == 50);
		CHECK(d[0].box.right() == 190);
		CHECK(d[0].box.y == 100 && d[0].box.h == 20);
	}

	// Low-confidence words are ignored when min_confidence is set.
	MatcherConfig strict;
	strict.min_confidence = 60.0f;
	PiiMatcher ms(strict);
	auto line = make_line("mail bob@example.com");
	for (auto &w : line.words)
		w.confidence = 10.0f;
	CHECK(ms.match({line}).empty());
	line.words[1].confidence = 90.0f;
	CHECK(ms.match({line}).size() == 1);
}

static void test_rects()
{
	Rect a{0, 0, 10, 10}, b{5, 5, 10, 10}, c{100, 100, 5, 5};
	CHECK(a.intersects(b));
	CHECK(!a.intersects(c));
	CHECK((a.united(b) == Rect{0, 0, 15, 15}));
	CHECK((a.padded(2) == Rect{-2, -2, 14, 14}));
	CHECK((a.padded(2).clipped(100, 100) == Rect{0, 0, 12, 12}));
	CHECK((Rect{3, 3, 3, 3}.scaled(0.5, 0.5) == Rect{1, 1, 2, 2}));
	auto merged = merge_rects({a, b, c, Rect{}});
	CHECK(merged.size() == 2);
}

static void test_tracker()
{
	const uint64_t ms = 1000000ULL;
	const Rect A{0, 0, 10, 10};
	const Rect B{50, 50, 10, 10};

	{
		RegionTracker t;
		t.set_persistence_ns(500 * ms);
		CHECK(!t.verified(1));
		t.add_result(10, 1000 * ms, {A});
		CHECK(t.verified(10));
		CHECK(t.verified(5));
		CHECK(!t.verified(11));
		// Look-ahead: a frame captured shortly before the scanned frame.
		CHECK(t.regions_for(900 * ms).size() == 1);
		// Regression (blinking): with no newer scan the box must stay up,
		// however long the next scan takes.
		CHECK(t.regions_for(1400 * ms).size() == 1);
		CHECK(t.regions_for(9000 * ms).size() == 1);
	}

	{
		// Slow scans (2 s each) with persist far shorter than the scan time:
		// text visible in every scan must be covered continuously.
		RegionTracker t;
		t.set_persistence_ns(100 * ms);
		t.add_result(1, 1000 * ms, {A});
		t.add_result(2, 3000 * ms, {A});
		t.add_result(3, 5000 * ms, {A});
		for (uint64_t f = 1000; f <= 8000; f += 50)
			CHECK(t.regions_for(f * ms).size() == 1);
	}

	{
		// Text disappears: hold through one missed scan (default), then
		// expire `persist` after the second scan that did not see it.
		RegionTracker t;
		t.set_persistence_ns(500 * ms);
		t.add_result(1, 1000 * ms, {A});
		t.add_result(2, 2000 * ms, {});
		CHECK(t.regions_for(2500 * ms).size() == 1); // one miss tolerated
		t.add_result(3, 3000 * ms, {});
		CHECK(t.regions_for(3400 * ms).size() == 1);
		CHECK(t.regions_for(3600 * ms).empty());

		t.set_tolerated_misses(0);
		CHECK(t.regions_for(2400 * ms).size() == 1);
		CHECK(t.regions_for(2600 * ms).empty());
	}

	{
		// Look-back to the previous scan: text first seen at 2000 was not
		// there at 1000, so (delayed) frames after 1000 are covered.
		RegionTracker t;
		t.set_persistence_ns(200 * ms);
		t.add_result(1, 1000 * ms, {});
		t.add_result(2, 2000 * ms, {B});
		CHECK(t.regions_for(900 * ms).empty());
		CHECK(t.regions_for(1200 * ms).size() == 1);
	}

	{
		RegionTracker t;
		t.set_persistence_ns(100 * ms);
		for (uint64_t i = 1; i <= 10; i++)
			t.add_result(i, i * 1000 * ms, {A});
		t.prune(9000 * ms);
		CHECK(t.result_count() < 10);
		CHECK(t.regions_for(9000 * ms).size() == 1);
		CHECK(t.regions_for(10000 * ms).size() == 1);
		t.clear();
		CHECK(t.result_count() == 0 && !t.verified(0));
	}
}

static void test_image()
{
	Image img;
	img.width = 4;
	img.height = 2;
	img.channels = 4;
	img.pixels.assign(4 * 2 * 4, 0);
	for (size_t i = 0; i < img.pixels.size(); i += 4) {
		img.pixels[i + 0] = 255; // B
		img.pixels[i + 1] = 255; // G
		img.pixels[i + 2] = 255; // R
		img.pixels[i + 3] = 255;
	}
	Image g = to_grey(img);
	CHECK(g.channels == 1 && g.pixels.size() == 8);
	CHECK(g.pixels[0] >= 254);
	Image half = resize(img, 2, 1);
	CHECK(half.width == 2 && half.height == 1 && half.pixels[0] == 255);

	std::vector<uint8_t> padded(2 * 16, 7); // linesize 16 for width 2
	Image packed = image_from_bgra(padded.data(), 2, 2, 16);
	CHECK(packed.pixels.size() == 16 && packed.pixels[15] == 7);
}

int main()
{
	const std::vector<std::pair<const char *, std::function<void()>>> tests = {
		{"validators", test_validators},
		{"detectors", test_detectors},
		{"disabled", test_disabled_detectors},
		{"keywords/custom", test_keywords_and_custom},
		{"box mapping", test_box_mapping},
		{"rects", test_rects},
		{"tracker", test_tracker},
		{"image", test_image},
	};
	for (const auto &t : tests) {
		const int before = g_failures;
		t.second();
		std::printf("%s %s\n", g_failures == before ? "[ OK ]" : "[FAIL]", t.first);
	}
	std::printf("%d checks, %d failures\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
