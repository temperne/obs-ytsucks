#!/usr/bin/env bash
# Headless end-to-end test on Linux: runs real libobs (Xvfb + Mesa), shows
# tests/e2e/pii-sample.png through an image source with the PII filter and
# checks that the known PII areas come out black.
#
#   sudo apt install obs-studio libobs-dev xvfb libgl1-mesa-dri imagemagick \
#                    tesseract-ocr-eng
#   tests/e2e/run-e2e.sh <build-dir>          # build-dir contains obs-ytsucks.so
#
# Env: STYLE=0|1|2  DELAY=<frames>  FAILSAFE=1
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
build="$(cd "${1:?usage: run-e2e.sh <build-dir>}" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

g++ -std=c++17 -O1 -I/usr/include/obs "$here/obs-e2e.cpp" -o "$work/obs-e2e" -lobs -lX11
HOME="$work" timeout 90 xvfb-run -a "$work/obs-e2e" "$build/obs-ytsucks.so" "$repo/data" \
  "$here/pii-sample.png" "$work/out.raw" 8
convert -size 1280x720 -depth 8 "bgra:$work/out.raw" -alpha off "$build/e2e-output.png"

# Mean brightness (0..1) of a crop; PII crops must be ~black, the benign line must not be.
mean() { convert "$build/e2e-output.png" -crop "$1" -colorspace gray -format '%[fx:mean]' info:; }
fail=0
check_dark() { local m; m=$(mean "$1"); echo "$2: mean=$m"; awk -v m="$m" 'BEGIN{exit !(m < 0.1)}' || { echo "  FAIL: not redacted"; fail=1; }; }
check_light() { local m; m=$(mean "$1"); echo "$2: mean=$m"; awk -v m="$m" 'BEGIN{exit !(m > 0.6)}' || { echo "  FAIL: benign text hidden"; fail=1; }; }

if [[ "${STYLE:-0}" == 0 ]]; then
  check_dark 400x30+300+275 email
  check_dark 250x30+330+425 phone
  check_dark 380x30+200+575 card
fi
check_light 600x40+80+115 benign
echo "output: $build/e2e-output.png"
exit $fail
