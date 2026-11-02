"""Masking personal details before any text leaves the server.

Before evidence is sent to an external LLM, phone numbers, emails, UPI IDs,
bank account and card numbers, Aadhaar and PAN numbers and OTP-style codes
are replaced with placeholders like [PHONE_1]. Link paths are masked too
(they can carry personal tokens), keeping only the website name, which the
explanation needs. The mapping never leaves the server; placeholders in the
LLM's answer are swapped back for the user.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Order matters: more specific patterns first, so a card number isn't read as a phone number.
_PATTERNS = [
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]*[a-z]\b", re.I)),
    ("UPI", re.compile(r"\b[\w.-]{2,}@[a-z]{2,}\b", re.I)),
    ("LINK", re.compile(r"\b((?:https?://)?(?:www\.)?[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}(?::\d+)?)(/[^\s\"'<>]*)", re.I)),
    ("CARD", re.compile(r"(?<!\d)(?:\d{4}[ -]?){3}\d{1,7}(?!\d)")),
    ("AADHAAR", re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)")),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    ("ACCOUNT", re.compile(r"(?<![\d+])\d{11,18}(?!\d)")),   # long unbroken numbers: accounts, not phones
    ("PHONE", re.compile(r"(?<![\w/])(?:\+?\d{1,3}[ -]?)?(?:\d[ -]?){9,11}\d(?![\w/])|\b9X{6,}\d*\b|\b\d{2,5}X{3,}[\dX ]*\d\b", re.I)),
    ("ACCOUNT", re.compile(r"\b(?:a/?c|acct|account)\s*(?:no\.?|number)?\s*[:#]?\s*[xX*]*\d{3,}\b", re.I)),
    # OTP-style codes. Not parts of dates (12/10/2024), times, amounts or decimals.
    ("CODE", re.compile(r"(?<![\d.,₹$/:-])\b\d{4,8}\b(?![.,/:-]?\d)")),
]


@dataclass
class Masker:
    """Keeps one mapping across a whole evidence report, so the same number
    gets the same placeholder everywhere."""
    mapping: dict[str, str] = field(default_factory=dict)   # placeholder -> original
    _reverse: dict[str, str] = field(default_factory=dict)  # original -> placeholder
    _counts: dict[str, int] = field(default_factory=dict)

    def _placeholder(self, kind: str, original: str) -> str:
        if original in self._reverse:
            return self._reverse[original]
        self._counts[kind] = self._counts.get(kind, 0) + 1
        ph = f"[{kind}_{self._counts[kind]}]"
        self.mapping[ph] = original
        self._reverse[original] = ph
        return ph

    def mask(self, text: str) -> str:
        for kind, rx in _PATTERNS:
            if kind == "LINK":
                text = rx.sub(lambda m: m.group(1) + ("/" + self._placeholder("PATH", m.group(2)[1:])
                                                      if len(m.group(2)) > 1 else m.group(2)), text)
            else:
                text = rx.sub(lambda m, k=kind: self._placeholder(k, m.group(0)), text)
        return text

    def mask_obj(self, obj):
        """Mask every string inside a JSON-like structure."""
        if isinstance(obj, str):
            return self.mask(obj)
        if isinstance(obj, list):
            return [self.mask_obj(x) for x in obj]
        if isinstance(obj, dict):
            return {k: self.mask_obj(v) for k, v in obj.items()}
        return obj

    def unmask(self, text: str) -> str:
        for ph, original in self.mapping.items():
            text = text.replace(ph, original)
        return text
