"""One entry point for every uploaded file.

  1. Work out what the file really is from its bytes (inspectors.classify).
  2. Apply that type's size limit.
  3. Inspect it: images in this process (they're decoded into plain pixels
     first); PDFs, APKs and emails in a disposable sandbox process with time
     and memory limits.
  4. Return text for the normal analysis, extra red flags, and facts to show.

Nothing is written to disk, opened, installed or executed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import inspectors, sandbox
from .safety import UnsafeInput


@dataclass
class FileResult:
    name: str
    kind: str
    text: str = ""                                    # goes into the normal analysis
    signals: list[dict] = field(default_factory=list)  # extra red flags found in the file
    facts: list[str] = field(default_factory=list)     # shown to the user
    method: str = ""                                    # how it was read
    external: bool = False                              # was it sent to an outside service?
    ocr_quality: float | None = None                    # 0-100 word confidence, for photos read by OCR

    @property
    def label(self) -> str:
        return inspectors.KINDS.get(self.kind, self.kind)

    def summary(self) -> dict:
        """For the evidence report (no raw file content)."""
        out = {"name": self.name[:120], "type": self.label, "findings": self.facts,
               "red_flags": [s["id"] for s in self.signals], "read_with": self.method}
        if self.ocr_quality is not None:
            out["text_reading_quality"] = round(self.ocr_quality)
        return out


def inspect_upload(data: bytes, name: str, allow_online: bool = False) -> FileResult:
    """Raises UnsafeInput (with a message safe to show) if the file is refused."""
    from . import ocr, safety

    kind = inspectors.classify(data)
    limit = inspectors.SIZE_LIMITS.get(kind)
    if limit and len(data) > limit * 1024 * 1024:
        raise UnsafeInput(f"This {inspectors.KINDS[kind].lower()} is larger than {limit} MB, so it wasn't checked.")

    if kind == "image":
        img = safety.load_image(data)
        try:
            o = ocr.read_image(data, allow_online)
        except ocr.OCRUnavailable:
            # Text can't be read here, but QR codes can still be decoded.
            o = ocr.OcrResult("", "not read (no text reader installed)", 0.0, False,
                              "The text in the photo couldn't be read here (no text reader installed).")
        codes = inspectors.read_qr_codes(img)
        qr_facts, qr_signals, qr_text = inspectors.qr_findings(codes, o.text)
        pay_facts, pay_signals = inspectors.payment_screenshot_findings(o.text)
        facts = qr_facts + pay_facts + ([o.note] if o.note else [])
        text = "\n".join(t for t in (o.text, qr_text) if t)
        quality = None if (o.external or not o.text) else o.quality   # no score without local OCR text
        return FileResult(name, kind, text, qr_signals + pay_signals, facts, o.method, o.external, quality)

    if kind in ("pdf", "apk", "email"):
        try:
            found = sandbox.run_isolated(kind, data)
        except sandbox.SandboxError as e:
            raise UnsafeInput(str(e))
        text = f"Attached file: {name}\n{found['text']}" if kind == "apk" else found["text"]
        return FileResult(name, kind, text, found["signals"], found["facts"], "inspected in a sandbox, not opened")

    if kind in ("audio", "video"):
        return FileResult(name, kind, "", [], list(inspectors.MEDIA_FACTS[kind]), "not analysed")

    if kind == "zip":
        raise UnsafeInput("ZIP archives aren't opened here, because they can hide apps and programs. "
                          "Don't open ZIP files from people you don't know.")
    raise UnsafeInput("This type of file can't be checked. Supported: screenshots and photos, PDFs, "
                      "emails saved as .eml, and Android apps (.apk).")
