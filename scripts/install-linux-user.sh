#!/usr/bin/env bash
# Build obs-ytsucks and install it for the current user on Linux.
#
#   scripts/install-linux-user.sh            # native OBS (apt / PPA / source)
#   scripts/install-linux-user.sh --flatpak  # Flatpak OBS (see note below)
#
# Native OBS 30+ loads per-user plugins from ~/.config/obs-studio/plugins.
# Needs: build-essential cmake ninja-build pkg-config libobs-dev libsimde-dev
#        libtesseract-dev tesseract-ocr-eng
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
build="$repo/build-user"

dest="${XDG_CONFIG_HOME:-$HOME/.config}/obs-studio/plugins/obs-ytsucks"
if [[ "${1:-}" == "--flatpak" ]]; then
  # Note: the Flatpak sandbox does not ship libtesseract; the plugin will load
  # but report "OCR unavailable" unless tesseract is provided inside it.
  dest="$HOME/.var/app/com.obsproject.Studio/config/obs-studio/plugins/obs-ytsucks"
fi

cmake -S "$repo" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build "$build"

mkdir -p "$dest/bin/64bit" "$dest/data"
install -m 755 "$build/obs-ytsucks.so" "$dest/bin/64bit/obs-ytsucks.so"
cp -r "$repo/data/." "$dest/data/"

echo "Installed to $dest"
echo "Restart OBS, then: right-click a source > Filters > + > 'PII Redaction (OCR)'."
