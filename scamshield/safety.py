"""Input limits and safe handling of uploaded images.

People upload private chats and banking screenshots, and attackers can upload
files built to crash or exploit image decoders. So:

  * file types are checked from the file's first bytes, not its name;
  * image dimensions are checked *before* the pixels are decoded, so a small
    file that expands into billions of pixels ("decompression bomb") is
    rejected without using the memory;
  * images are decoded once into a fresh in-memory copy (which also drops
    EXIF metadata such as GPS location) and downscaled for OCR;
  * nothing is written to disk by this app.
"""
from __future__ import annotations

import io
import warnings

from PIL import Image, ImageOps

MAX_MESSAGE_CHARS = 20_000      # about 8 pages; long chat exports keep their most recent part
MAX_IMAGE_BYTES = 8 * 1024 * 1024
MAX_IMAGES = 5
MAX_IMAGE_PIXELS = 40_000_000   # e.g. 8000 x 5000; real screenshots are far smaller
OCR_MAX_SIDE = 2400             # longer sides are downscaled before OCR: faster, same accuracy

# Make Pillow refuse oversized images everywhere in this process, not just warn.
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

_SIGNATURES = {
    "PNG": (b"\x89PNG\r\n\x1a\n",),
    "JPEG": (b"\xff\xd8\xff",),
    "WEBP": (b"RIFF",),   # plus "WEBP" at bytes 8-12, checked below
}


class UnsafeInput(ValueError):
    """Input rejected for safety; the message is safe to show to the user."""


def limit_text(text: str) -> tuple[str, bool]:
    """Keep messages to a sensible size. For long chats the most recent part
    is kept, since that's where requests for money or codes usually are."""
    if len(text) <= MAX_MESSAGE_CHARS:
        return text, False
    cut = text[-MAX_MESSAGE_CHARS:]
    nl = cut.find("\n")
    if 0 <= nl < 500:   # start at a whole line
        cut = cut[nl + 1:]
    return cut, True


def sniff_image_type(data: bytes) -> str | None:
    head = data[:16]
    if head.startswith(_SIGNATURES["PNG"][0]):
        return "PNG"
    if head.startswith(_SIGNATURES["JPEG"][0]):
        return "JPEG"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "WEBP"
    return None


def load_image(data: bytes) -> Image.Image:
    """Validate and decode an uploaded image. Raises UnsafeInput with a
    user-friendly reason if anything is wrong."""
    if len(data) > MAX_IMAGE_BYTES:
        raise UnsafeInput(f"This image is larger than {MAX_IMAGE_BYTES // (1024 * 1024)} MB. "
                          "Try a screenshot instead of a full-resolution photo.")
    kind = sniff_image_type(data)
    if kind is None:
        raise UnsafeInput("This file isn't a PNG, JPEG or WEBP image, whatever its name says.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            img = Image.open(io.BytesIO(data))
            if img.format != kind:
                raise UnsafeInput("This file's contents don't match an image type we accept.")
            w, h = img.size                       # read from the header, nothing decoded yet
            if w * h > MAX_IMAGE_PIXELS or w > 20_000 or h > 20_000:
                raise UnsafeInput("This image has far more pixels than a screenshot. Try a screenshot instead.")
            img.seek(0)                           # animated images: first frame only
            img = ImageOps.exif_transpose(img)    # fix phone rotation
            clean = img.convert("RGB")            # fresh pixel copy, metadata dropped
    except UnsafeInput:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise UnsafeInput("This image has far more pixels than a screenshot. Try a screenshot instead.")
    except Exception:
        raise UnsafeInput("This image couldn't be opened. It may be damaged; try taking the screenshot again.")
    if max(clean.size) > OCR_MAX_SIDE:
        scale = OCR_MAX_SIDE / max(clean.size)
        clean = clean.resize((round(clean.width * scale), round(clean.height * scale)), Image.LANCZOS)
    return clean


def to_png_bytes(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
