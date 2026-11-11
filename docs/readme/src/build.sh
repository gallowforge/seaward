#!/usr/bin/env bash
# Rebuild every README picture of Seaward in Glass, dark and light, wide and phone.
#
#   make shots                                 builds bin/seaward and the demo, installs this folder's two packages, runs this
#   ./build.sh [the binary] [the built demo]   the same without those builds (defaults: bin/seaward and pages/)
#   ./build.sh numbers                         only the numbers band, from numbers.json; nothing is captured
#
# Needs: node with this folder's packages (npm ci: playwright and three), a Chromium that playwright can launch
# (a GPU helps; the scenes are WebGL), ImageMagick, and python3 with Pillow and NumPy. The whole build also runs
# `make lab` for the kernel picture, so it needs what that needs: Linux, and the firewall tools the lab drives.
# capture.cjs runs the command-line sessions for real in a throwaway folder, serves the built demo on a free port
# and photographs it in its night theme and its day theme while its own controls are used: the lane of port 5432
# is opened, its packet is drawn rule by rule, and the fixed server is chosen in the sample switcher. render.cjs
# composes the glass scenes from layouts.js; ImageMagick writes the stills as WebP. The hero is a loop at 12 frames
# a second: render.cjs writes one turn of it as frames and loop.py packs them.
# Everything on the way is written under ../build (Chromium's scratch too), and none of it is needed afterwards:
# the pictures in docs/readme stand on their own.
set -euo pipefail
SRC=$(cd "$(dirname "$0")" && pwd)
OUT=$(cd "$SRC/.." && pwd)
ROOT=$(cd "$OUT/../.." && pwd)
BUILD="$OUT/build"
PANELS="exposed why kernel unknown snapshot"
mkdir -p "$BUILD/png" "$BUILD/loop" "$BUILD/tmp"
export TMPDIR="$BUILD/tmp"

webp() { magick "$1" -strip -quality 88 -define webp:method=6 "$OUT/$(basename "$1" .png).webp"; }

if [ "${1:-}" = numbers ]; then
  jobs=()
  for t in dark light; do
    jobs+=("numbers:$t:still:$BUILD/png/numbers-$t.png" "numbers-phone:$t:still:$BUILD/png/numbers-$t-phone.png")
  done
  node "$SRC/render.cjs" "${jobs[@]}"
  for f in "$BUILD"/png/numbers-*.png; do webp "$f"; done
  du -ch "$OUT"/numbers-*.webp | tail -1
  exit 0
fi

BIN="${1:-$ROOT/bin/seaward}"
PAGES="${2:-$ROOT/pages}"
[ -x "$BIN" ] || { echo "build.sh: no binary at $BIN (make build)" >&2; exit 1; }
[ -f "$PAGES/index.html" ] || { echo "build.sh: no built demo in $PAGES (make demo)" >&2; exit 1; }

node "$SRC/capture.cjs" "$BIN" "$PAGES"
# frames left by an earlier build with a longer loop would be packed into this one
find "$BUILD/png" "$BUILD/loop" -type f -name '*.png' -delete

jobs=()
for t in dark light; do
  for l in numbers $PANELS; do
    jobs+=("$l:$t:still:$BUILD/png/$l-$t.png" "$l-phone:$t:still:$BUILD/png/$l-$t-phone.png")
  done
  jobs+=("hero:$t:anim:loop:$BUILD/loop/hero-$t" "hero-phone:$t:anim:loop:$BUILD/loop/hero-$t-phone")
done
node "$SRC/render.cjs" "${jobs[@]}"
for f in "$BUILD"/png/*.png; do webp "$f"; done
# the last number is the WebP quality; a still part of the loop is sent once, so quality costs little here
for t in dark light; do
  python3 "$SRC/loop.py" "$BUILD/loop/hero-$t" "$OUT/hero-$t.webp" 12 70
  python3 "$SRC/loop.py" "$BUILD/loop/hero-$t-phone" "$OUT/hero-$t-phone.webp" 12 66
done

# The plate for the repository's social preview (Settings, Social preview on GitHub) and for the demo's link
# card (`make pages` copies it there), 1280 x 640, dark.
node "$SRC/render.cjs" "social:dark:still:$OUT/social.png"
magick "$OUT/social.png" -strip -define png:compression-level=9 "$OUT/social.png"

du -ch "$OUT"/*.webp "$OUT/social.png" | tail -1
