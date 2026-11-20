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

static void raw_cb(void *, struct video_data *frame)
{
	std::lock_guard<std::mutex> l(g_mtx);
	g_linesize = frame->linesize[0];
	g_frame.assign(frame->data[0], frame->data[0] + (size_t)g_linesize * 720);
	g_frames++;
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
	if (getenv("FAILSAFE"))
		obs_data_set_bool(fs, "fail_safe", true);
	obs_source_t *filter = obs_source_create("pii_redact_filter", "pii", fs, nullptr);
	obs_data_release(fs);
	if (!filter) {
		printf("filter create failed\n");
		return 7;
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

	obs_set_output_source(0, nullptr);
	obs_source_release(filter);
	obs_source_release(img);
	obs_shutdown();
	XCloseDisplay(dpy);
	return 0;
}
