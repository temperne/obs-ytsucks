// Headless end-to-end test: real libobs + image source + our filter.
#include <obs.h>
#include <obs-nix-platform.h>
#include <X11/Xlib.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>
#include <cstdlib>

static std::mutex g_mtx;
static std::vector<uint8_t> g_frame;
static uint32_t g_linesize = 0;
static std::atomic<int> g_frames{0};
// Per-frame flicker tracking of the e-mail area (x 300..700, y 275..305).
static int g_first_redacted = -1;
static int g_flicker_frames = 0;
// Leak metric: PII in the sample image is drawn in pure red; count red
// pixels that reach the output.
static std::vector<int> g_red;

static void raw_cb(void *, struct video_data *frame)
{
	std::lock_guard<std::mutex> l(g_mtx);
	g_linesize = frame->linesize[0];
	g_frame.assign(frame->data[0], frame->data[0] + (size_t)g_linesize * 720);
	double sum = 0;
	for (int y = 275; y < 305; y++)
		for (int x = 300; x < 700; x++)
			sum += frame->data[0][(size_t)y * g_linesize + x * 4 + 1];
	int red = 0;
	for (int y = 0; y < 720; y++) {
		const uint8_t *row = frame->data[0] + (size_t)y * g_linesize;
		for (int x = 0; x < 1280; x++) {
			const uint8_t *p = row + x * 4; // BGRA
			if (p[2] > 150 && p[1] < 100 && p[0] < 100)
				red++;
		}
	}
	g_red.push_back(red);
	const bool dark = sum / (30.0 * 400.0) < 25.0;
	const int n = g_frames++;
	if (dark && g_first_redacted < 0)
		g_first_redacted = n;
	else if (!dark && g_first_redacted >= 0)
		g_flicker_frames++;
}

static bool load(const char *bin, const char *data)
{
	obs_module_t *m = nullptr;
	if (obs_open_module(&m, bin, data) != MODULE_SUCCESS) {
		printf("open fail %s\n", bin);
		return false;
	}
	if (!obs_init_module(m)) {
		printf("init fail %s\n", bin);
		return false;
	}
	return true;
}

int main(int argc, char **argv)
{
	if (argc < 5)
		return 2;
	const char *plugin_so = argv[1], *plugin_data = argv[2], *image = argv[3], *out_raw = argv[4];
	Display *dpy = XOpenDisplay(nullptr);
	if (!dpy) {
		printf("no X display\n");
		return 2;
	}
	obs_set_nix_platform(OBS_NIX_PLATFORM_X11_EGL);
	obs_set_nix_platform_display(dpy);
	if (!obs_startup("en-US", nullptr, nullptr))
		return 3;

	struct obs_video_info ovi = {};
	ovi.graphics_module = "libobs-opengl.so.30";
	ovi.fps_num = 30;
	ovi.fps_den = 1;
	ovi.base_width = ovi.output_width = 1280;
	ovi.base_height = ovi.output_height = 720;
	ovi.output_format = VIDEO_FORMAT_BGRA;
	ovi.colorspace = VIDEO_CS_709;
	ovi.range = VIDEO_RANGE_FULL;
	ovi.gpu_conversion = true;
	ovi.scale_type = OBS_SCALE_BICUBIC;
	int rv = obs_reset_video(&ovi);
	if (rv != OBS_VIDEO_SUCCESS) {
		printf("reset_video %d\n", rv);
		return 4;
	}

	if (!load("/usr/lib/x86_64-linux-gnu/obs-plugins/image-source.so", "/usr/share/obs/obs-plugins/image-source"))
		return 5;
	if (!load(plugin_so, plugin_data))
		return 6;
	obs_post_load_modules();

	obs_data_t *is = obs_data_create();
	obs_data_set_string(is, "file", image);
	obs_source_t *img = obs_source_create("image_source", "img", is, nullptr);
	obs_data_release(is);

	obs_data_t *fs = obs_data_create();
	obs_data_set_int(fs, "interval_ms", 100);
	if (getenv("STYLE"))
		obs_data_set_int(fs, "style", atoi(getenv("STYLE")));
	if (getenv("DELAY"))
		obs_data_set_int(fs, "delay_frames", atoi(getenv("DELAY")));
	if (getenv("PERSIST"))
		obs_data_set_int(fs, "persist_ms", atoi(getenv("PERSIST")));
	if (getenv("INTERVAL"))
		obs_data_set_int(fs, "interval_ms", atoi(getenv("INTERVAL")));
	if (getenv("FAILSAFE"))
		obs_data_set_bool(fs, "fail_safe", true);
	obs_source_t *filter = obs_source_create("pii_redact_filter", "pii", fs, nullptr);
	obs_data_release(fs);
	if (!filter) {
		printf("filter create failed\n");
		return 7;
	}
	if (getenv("SCROLL")) {
		// Built-in scroll filter in front of ours: a continuously scrolling page.
		if (!load("/usr/lib/x86_64-linux-gnu/obs-plugins/obs-filters.so",
			  "/usr/share/obs/obs-plugins/obs-filters"))
			return 8;
		obs_data_t *ss = obs_data_create();
		obs_data_set_double(ss, "speed_y", atof(getenv("SCROLL")));
		obs_source_t *scroll = obs_source_create("scroll_filter", "scroll", ss, nullptr);
		obs_data_release(ss);
		obs_source_filter_add(img, scroll);
		obs_source_release(scroll);
	}
	obs_source_filter_add(img, filter);
	obs_set_output_source(0, img);

	struct video_scale_info conv = {};
	conv.format = VIDEO_FORMAT_BGRA;
	conv.width = 1280;
	conv.height = 720;
	conv.colorspace = VIDEO_CS_709;
	conv.range = VIDEO_RANGE_FULL;
	obs_add_raw_video_callback(&conv, raw_cb, nullptr);

	std::this_thread::sleep_for(std::chrono::seconds(argc > 5 ? atoi(argv[5]) : 6));

	obs_remove_raw_video_callback(raw_cb, nullptr);
	{
		std::lock_guard<std::mutex> l(g_mtx);
		FILE *f = fopen(out_raw, "wb");
		for (int y = 0; y < 720; y++)
			fwrite(g_frame.data() + (size_t)y * g_linesize, 1, 1280 * 4, f);
		fclose(f);
	}
	printf("frames captured: %d\n", g_frames.load());
	printf("first redacted frame: %d, unredacted frames after that: %d\n", g_first_redacted, g_flicker_frames);
	{
		// Skip the first 2 s (start-up: first scans) then report leaks.
		std::lock_guard<std::mutex> l(g_mtx);
		const size_t skip = 60;
		int leak_frames = 0, max_red = 0;
		long total = 0;
		for (size_t i = skip; i < g_red.size(); i++) {
			if (g_red[i] > 30)
				leak_frames++;
			max_red = g_red[i] > max_red ? g_red[i] : max_red;
			total += g_red[i];
		}
		const size_t n = g_red.size() > skip ? g_red.size() - skip : 0;
		printf("leak: %d of %zu frames show PII pixels (max %d px, avg %.1f px)\n", leak_frames, n, max_red,
		       n ? (double)total / n : 0.0);
	}

	obs_set_output_source(0, nullptr);
	obs_source_release(filter);
	obs_source_release(img);
	obs_shutdown();
	XCloseDisplay(dpy);
	return 0;
}
