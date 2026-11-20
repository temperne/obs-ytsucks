// Minimal self-contained test runner for src/core (no external framework).
#include "image.hpp"
#include "pii-matcher.hpp"
#include "bands.hpp"
#include "motion-tracker.hpp"

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
	CHECK(has_kind(m, "jasonatensen@emiail'eam", PiiKind::Email));
	CHECK(has_kind(m, "dasonajensen@emailicom", PiiKind::Email));
	CHECK(!has_kind(m, "follow @someone", PiiKind::Email));
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
	CHECK(has_kind(m, "Tucson, Arizona 85705", PiiKind::StreetAddress));
	CHECK(has_kind(m, "919 N. Stone Ave., Apt. #5305", PiiKind::StreetAddress));
	{
		// The unit number must be part of the match.
		bool covers_unit = false;
		for (const auto &sp : m.match_text("919 N. Stone Ave., Apt. #5305"))
			if (sp.kind == PiiKind::StreetAddress && sp.end == 29)
				covers_unit = true;
		CHECK(covers_unit);
	}
	CHECK(has_kind(m, "402-598-1285", PiiKind::Phone));
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

// Synthetic "web page": random texture, rendered with a vertical scroll.
static Image page_frame(int w, int h, int scroll_y)
{
	Image img;
	img.width = static_cast<uint32_t>(w);
	img.height = static_cast<uint32_t>(h);
	img.channels = 1;
	img.pixels.resize(static_cast<size_t>(w) * h);
	for (int y = 0; y < h; y++) {
		for (int x = 0; x < w; x++) {
			const uint32_t py = static_cast<uint32_t>(y + scroll_y + 1000);
			uint32_t v = static_cast<uint32_t>(x) * 73856093u ^ py * 19349663u;
			v ^= v >> 13;
			v *= 0x5bd1e995u;
			v ^= v >> 15;
			img.pixels[static_cast<size_t>(y) * w + x] = static_cast<uint8_t>(v & 0xFF);
		}
	}
	return img;
}

static void test_match_patch()
{
	Image a = page_frame(128, 96, 0);
	Image b = page_frame(128, 96, 5); // content moved up by 5
	int dx = 0, dy = 0;
	double err = 0;
	match_patch(a, b, Rect{40, 40, 30, 10}, 0, 0, 16, dx, dy, err);
	CHECK(dx == 0 && dy == -5);
	CHECK(err >= 0 && err < 1.0);
	// Prediction already right: early exit.
	match_patch(a, b, Rect{40, 40, 30, 10}, 0, -5, 16, dx, dy, err);
	CHECK(dx == 0 && dy == -5);
	// Large sparse-sample motion with a bigger radius.
	Image c = page_frame(128, 96, 30);
	match_patch(a, c, Rect{40, 50, 30, 10}, 0, 0, 40, dx, dy, err);
	CHECK(dx == 0 && dy == -30);
}

static void test_motion_tracker()
{
	const uint64_t ms = 1000000ULL;
	// Thumbnails are 1/4 of the 512x384 "full" resolution.
	const uint32_t FW = 512, FH = 384;

	{
		// Static screen: box stays, lifetime rule holds.
		MotionTracker t;
		MotionConfig cfg;
		cfg.persist_ns = 500 * ms;
		t.set_config(cfg);
		for (uint64_t f = 1; f <= 10; f++)
			t.add_frame(f, f * 33 * ms, page_frame(128, 96, 0), FW, FH);
		t.add_scan(10, {Rect{100, 100, 80, 20}});
		auto v = t.view(0);
		CHECK(v.verified(10) && !v.verified(11));
		CHECK(v.rects_for(10, 330 * ms).size() == 1);
		// Far in the future with no newer scan: still covered.
		CHECK(v.rects_for(500, 99999 * ms).size() == 1);
		// Two scans that miss it -> dead after persist.
		t.add_frame(20, 660 * ms, page_frame(128, 96, 0), FW, FH);
		t.add_scan(20, {});
		CHECK(t.view(0).rects_for(20, 660 * ms).size() == 1);
		t.add_frame(30, 990 * ms, page_frame(128, 96, 0), FW, FH);
		t.add_scan(30, {});
		auto v2 = t.view(0);
		CHECK(v2.rects_for(30, 1400 * ms).size() == 1);
		CHECK(v2.rects_for(30, 1600 * ms).empty());
	}

	{
		// Scrolling page, sampled every 3rd frame, 2 thumb px per frame
		// (= 8 full px per frame). OCR result for frame 3 arrives late
		// (after frame 15 was sampled): the box must land where the text
		// is at frame 15, and extrapolate beyond.
		MotionTracker t;
		const int speed = 2; // thumbnail px per frame
		for (uint64_t f = 0; f <= 15; f += 3)
			t.add_frame(f + 1, (f + 1) * 33 * ms, page_frame(128, 96, static_cast<int>(f) * speed), FW, FH);
		// Text at full-res y=200 in frame 4 (scroll 3*2 thumb px).
		const Rect det{100, 200, 80, 16};
		t.add_scan(4, {det});
		auto v = t.view(0);
		auto at16 = v.rects_for(16, 16 * 33 * ms);
		CHECK(at16.size() == 1);
		if (!at16.empty()) {
			// Expected y at frame 16: 200 - (16-4)*speed*4 = 104.
			CHECK(std::abs(at16[0].y - 104) <= 4);
		}
		// Velocity measured: about -8 full px per frame.
		CHECK(t.max_speed() > 6.0 && t.max_speed() < 10.0);
		// Extrapolated frame 18 (not sampled): box widened to cover y=88.
		auto at18 = v.rects_for(18, 18 * 33 * ms);
		CHECK(at18.size() == 1);
		if (!at18.empty()) {
			CHECK(at18[0].y <= 88 && at18[0].bottom() >= 88 + 16);
		}
	}

	{
		// Look-back: in delayed output, frames between the previous scan
		// and the scan that first saw the text are covered too.
		MotionTracker t;
		for (uint64_t f = 1; f <= 9; f += 2)
			t.add_frame(f, f * 33 * ms, page_frame(128, 96, 0), FW, FH);
		t.add_scan(3, {});
		t.add_scan(9, {Rect{40, 40, 40, 12}});
		auto v = t.view(0);
		CHECK(v.rects_for(2, 66 * ms).empty());
		CHECK(v.rects_for(4, 132 * ms).size() == 1);
	}
}

static void test_bands()
{
	auto b = plan_bands(1080, 4, 60, 100);
	CHECK(b.size() == 4);
	CHECK(b.front().y == 0 && b.back().y + b.back().h == 1080);
	for (size_t i = 1; i < b.size(); i++)
		CHECK(b[i].y + 60 <= b[i - 1].y + b[i - 1].h); // overlap >= 60
	CHECK(plan_bands(200, 8, 40, 150).size() == 1);
	CHECK(plan_bands(0, 4, 10, 10).empty());

	{
		// Two "windows": white with text-like noise | border | dark with noise,
		// plus a wide blank gap inside the white window.
		Image g;
		g.width = 200;
		g.height = 40;
		g.channels = 1;
		g.pixels.assign(200 * 40, 255);
		for (int y = 0; y < 40; y++)
			for (int x = 0; x < 200; x++) {
				uint8_t &p = g.pixels[static_cast<size_t>(y * 200 + x)];
				if (x >= 120)
					p = 30;
				const bool ink = ((x * 7 + y * 13) % 5) == 0;
				if (ink && ((x >= 10 && x < 50) || (x >= 80 && x < 115) || (x >= 130 && x < 190)))
					p = x >= 120 ? 220 : 0;
			}
		auto segs = split_columns(g, 0, 40);
		CHECK(segs.size() == 3);
		if (segs.size() == 3) {
			CHECK(segs[0].first <= 10 && segs[0].second >= 50 && segs[0].second < 80);
			CHECK(segs[1].first > 50 && segs[1].first <= 80 && segs[1].second <= 124);
			CHECK(segs[2].first >= 116 && segs[2].second >= 190);
		}
	}
	Image img = page_frame(64, 32, 0);
	Image c = crop(img, Rect{10, 5, 20, 8});
	CHECK(c.width == 20 && c.height == 8 && c.pixels[0] == img.pixels[5 * 64 + 10]);
	CHECK(mean_abs_diff(img, img) == 0.0);
	CHECK(mean_abs_diff(img, page_frame(64, 32, 1)) > 10.0);
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

	{
		// Dark tile gets inverted, light tile left alone.
		Image gimg;
		gimg.width = 8;
		gimg.height = 4;
		gimg.channels = 1;
		gimg.pixels.assign(32, 230);
		for (int y = 0; y < 4; y++)
			for (int x = 4; x < 8; x++)
				gimg.pixels[static_cast<size_t>(y * 8 + x)] = 20;
		normalize_polarity(gimg, 4);
		CHECK(gimg.pixels[0] == 230 && gimg.pixels[4] == 235);
	}
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
		{"match_patch", test_match_patch},
		{"motion tracker", test_motion_tracker},
		{"bands", test_bands},
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
