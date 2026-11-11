#!/usr/bin/env python3
"""Write a folder of frames (f0000.png, f0001.png, ...) as a looping animated WebP.

    loop.py <frames dir> <out.webp> <frames a second> <quality>

The stock encoders (ffmpeg's libwebp_anim, img2webp) compare each frame with the frame before it and skip every
block that moved less than a threshold. A slow fade moves less than that on each of its steps, so parts of it are
never sent and a ghost of the old picture stays on screen. This one compares each frame with what is on screen:

- a block of 8 x 8 pixels is sent when a pixel in it is more than EDGE levels away from what is shown, or when the
  block as a whole has shifted by more than FLAT levels (soft shadows and haze, where a step between neighbouring
  blocks would show);
- every other block is left transparent, so the picture under it stays as it was sent. The codec smooths across
  block edges, transparent or not, so the blocks around a sent one carry their own average colour, which keeps
  its edges clean. The rest of the frame is one flat colour, which costs next to nothing.

A part of the scene that holds still is therefore sent once and costs nothing after that, and before the lossy
coding no pixel is ever further than EDGE levels from its frame.

The first frame is the whole picture, and every turn of the loop opens by drawing it again, with the noise its
lossy coding left in it. A block that changed and was coded again would flicker at that moment, even where the
picture itself is back at what it was. So the blocks that are back for good (the first frame would not have to
be sent over them, by the rule above) are given the very pixels the first frame shows there:

- the frame in which the most blocks come back holds the first frame a second time: the same bytes, behind a mask
  that lets through every block that is back by then;
- after it, a block that comes back is drawn at once, without loss. A picture that also has blocks coded the
  usual way is stored as two frames that share its time.

The last frame of a turn then shows what the next turn opens with, and the still parts do not change where the
loop closes.

Needs Pillow (with WebP) and NumPy.
"""

import glob
import io
import os
import struct
import sys
from concurrent.futures import ProcessPoolExecutor

import numpy as np
from PIL import Image

BLOCK, EDGE, FLAT = 8, 6, 2
IMAGE = (b"ALPH", b"VP8 ", b"VP8L")


def chunks(riff):
    """The chunks of a RIFF file, each with its header."""
    at = 12
    while at < len(riff):
        size = struct.unpack("<I", riff[at + 4 : at + 8])[0]
        end = at + 8 + size + (size & 1)
        yield riff[at : at + 4], riff[at:end]
        at = end


def still(pixels, quality, lossless=False):
    """A frame, or the changed part of one, as a still WebP."""
    out = io.BytesIO()
    if lossless:
        Image.fromarray(pixels).save(out, "WEBP", lossless=True, quality=100, method=6)
    else:
        Image.fromarray(pixels).save(out, "WEBP", quality=quality, method=6, exact=True)
    return out.getvalue()


def image(riff, tags=IMAGE):
    """The image chunks of a still, which are what a frame of an animation holds."""
    return b"".join(data for tag, data in chunks(riff) if tag in tags)


def encode(job):
    """One frame of the animation: made already, or a still to code."""
    return job if isinstance(job, bytes) else image(still(*job))


def grown(blocks):
    """The blocks, and the eight around each of them."""
    high, wide = blocks.shape
    edged = np.pad(blocks, 1)
    return np.any([edged[y : y + high, x : x + wide] for y in range(3) for x in range(3)], axis=0)


def chunk(tag, payload):
    return tag + struct.pack("<I", len(payload)) + payload + (b"\0" if len(payload) & 1 else b"")


def u24(value):
    return struct.pack("<I", value)[:3]


def main(src, out, fps, quality):
    files = sorted(glob.glob(os.path.join(src, "f*.png")))
    if not files:
        sys.exit(f"loop.py: no frames in {src}")

    def load(path):
        return np.asarray(Image.open(path).convert("RGB"))

    def pixels(blocks):  # from one value a block to one a pixel
        return blocks.repeat(BLOCK, axis=0).repeat(BLOCK, axis=1)[:height, :width]

    def due(i):  # whole milliseconds that add up to the exact length of the loop
        return round((i + 1) * 1000 / fps) - round(i * 1000 / fps)

    def changed(now, then):  # the blocks of one picture that have to be sent over the other
        blocks = np.pad(now - then, pad).reshape(grid)
        moved, shifted = np.abs(blocks).max(axis=(1, 3, 4)), np.abs(blocks.mean(axis=(1, 3))).max(axis=2)
        return (moved > EDGE) | (shifted > FLAT)

    def box(blocks):  # the pixels around them; the corner sits on the codec's own grid of 16 pixels
        rows, cols = np.nonzero(blocks)
        y0, x0 = rows.min() // 2 * 2 * BLOCK, cols.min() // 2 * 2 * BLOCK
        return y0, min(height, (rows.max() + 1) * BLOCK), x0, min(width, (cols.max() + 1) * BLOCK)

    first = load(files[0]).astype(np.int16)
    opening = still(first.astype(np.uint8), quality)
    # the first frame as the viewer gets it
    opened = np.asarray(Image.open(io.BytesIO(opening)).convert("RGB"))
    shown = first.copy()  # what the viewer has on screen, as it was sent
    height, width = shown.shape[:2]
    pad = ((0, -height % BLOCK), (0, -width % BLOCK), (0, 0))  # up to whole blocks
    grid = ((height + pad[0][1]) // BLOCK, BLOCK, (width + pad[1][1]) // BLOCK, BLOCK, 3)
    # for every frame, the blocks that are back at the first frame's picture and stay there to the end
    home = [~changed(load(path), first) for path in files]
    for i in range(len(files) - 1, 0, -1):
        home[i - 1] &= home[i]
    peak = max(range(1, len(files)), key=lambda i: (home[i] & ~home[i - 1]).sum(), default=0)
    fresh = np.ones((grid[0], grid[2]), bool)  # the blocks that show the first frame exactly as it was coded
    frames, jobs, images = [[0, 0, width, height, due(0)]], [], [image(opening)]
    with ProcessPoolExecutor() as pool:
        for i, path in enumerate(files[1:], 1):
            frame = load(path).astype(np.int16)
            if frame.shape != shown.shape:
                sys.exit(f"loop.py: {path} is not {width} x {height}")
            held = home[i] if i >= peak else np.zeros_like(fresh)
            send, again = changed(frame, shown) & ~held, held & ~fresh
            parts = []
            if send.any():
                y0, y1, x0, x1 = box(send)
                mask = pixels(send)
                shown[mask] = frame[mask]
                fresh &= ~send
                mask, drawn = mask[y0:y1, x0:x1], frame[y0:y1, x0:x1]
                flat = np.pad(frame, pad, mode="edge").reshape(grid).mean(axis=(1, 3)).round()
                near, far = pixels(grown(send))[y0:y1, x0:x1, None], drawn.mean(axis=(0, 1)).round()
                part = np.where(mask[..., None], drawn, np.where(near, pixels(flat)[y0:y1, x0:x1], far))
                part = np.dstack([part, np.where(mask, 255, 0)]).astype(np.uint8)
                parts.append(([x0, y0, x1 - x0, y1 - y0], (part, quality)))
            if again.any():
                mask = pixels(again)
                shown[mask] = first[mask]
                fresh |= again
                seen = np.where(mask, 255, 0)
                if i == peak:  # the first frame once more: its own bytes, and the mask of a still made for it
                    part = np.dstack([np.zeros_like(opened), seen]).astype(np.uint8)
                    parts.append(([0, 0, width, height], image(still(part, quality), (b"ALPH",)) + images[0]))
                else:
                    y0, y1, x0, x1 = box(again)
                    part = np.dstack([opened[y0:y1, x0:x1], seen[y0:y1, x0:x1]]).astype(np.uint8)
                    parts.append(([x0, y0, x1 - x0, y1 - y0], (part, quality, True)))
            if not parts:  # nothing to draw: the frame before stays up longer
                frames[-1][4] += due(i)
                continue
            for n, (place, job) in enumerate(parts):
                half = due(i) // len(parts)
                frames.append([*place, half if n else due(i) - half * (len(parts) - 1)])
                jobs.append(job)
            if len(jobs) >= 32:
                images += pool.map(encode, jobs)
                jobs = []
        images += pool.map(encode, jobs)

    # an animation with alpha, looping for ever; the first frame replaces the canvas, the rest are laid over it
    body = chunk(b"VP8X", bytes([0x12, 0, 0, 0]) + u24(width - 1) + u24(height - 1))
    body += chunk(b"ANIM", bytes(4) + struct.pack("<H", 0))
    for n, ((x, y, w, h, ms), data) in enumerate(zip(frames, images, strict=True)):
        head = u24(x // 2) + u24(y // 2) + u24(w - 1) + u24(h - 1) + u24(ms) + bytes([0 if n else 2])
        body += chunk(b"ANMF", head + data)
    with open(out, "wb") as f:
        f.write(b"RIFF" + struct.pack("<I", 4 + len(body)) + b"WEBP" + body)
    seconds = sum(frame[4] for frame in frames) / 1000
    print(f"{os.path.basename(out)}: {len(files)} frames, {seconds:g} s, {(12 + len(body)) / 1e6:.2f} MB")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4]))
