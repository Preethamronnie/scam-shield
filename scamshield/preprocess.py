"""Preprocessing: clean the text, detect its language, and split conversations.

Everything downstream (rules, model, context engine) gets the same cleaned
text, so a scam can't dodge the rules with invisible characters or
look-alike letters.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# --- normalisation --------------------------------------------------------------
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\ufe00-\ufe0f]")
_CONTROL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Phones turn ' and " into curly quotes automatically; rules match the plain ones.
_PUNCT = str.maketrans({"\u2018": "'", "\u2019": "'", "\u201a": "'", "\u201b": "'", "\u2032": "'",
                        "\u201c": '"', "\u201d": '"', "\u201e": '"', "\u2033": '"',
                        "\u2013": "-", "\u2014": "-", "\u2212": "-", "\u2026": "...", "\u00a0": " "})
_REPEATED_PUNCT = re.compile(r"([!?.*~_=])\1{3,}")
_BLANK_LINES = re.compile(r"\n{3,}")
_SPACES = re.compile(r"[ \t]+")
_LATIN_WORD = re.compile(r"[a-z]+")


def normalize(text: str) -> str:
    """Clean text so rules and the model see what a person would read.

    * NFKC turns full-width and styled letters (ｆｒｅｅ, 𝐅𝐫𝐞𝐞) into plain ones.
    * Invisible and control characters are removed: a common trick to break up
      words like O\u200bT\u200bP so filters miss them.
    * Curly quotes and dashes become plain ones (so "Don’t share" is read as "Don't share").
    * Noise like "!!!!!!!!" is shortened to "!!!", keeping the emphasis.
    Meaningful punctuation is kept: links, @, ₹, %, decimal points and line breaks.
    """
    text = unicodedata.normalize("NFKC", text or "")
    text = _INVISIBLE.sub("", text)
    text = _CONTROL.sub("", text)
    text = text.translate(_PUNCT)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _REPEATED_PUNCT.sub(r"\1\1\1", text)
    text = _SPACES.sub(" ", text)
    text = _BLANK_LINES.sub("\n\n", text)
    return "\n".join(line.strip() for line in text.split("\n")).strip()


# --- language detection ------------------------------------------------------------
_SCRIPTS = [
    ("Hindi / Marathi", "Devanagari", "\u0900", "\u097f"),
    ("Bengali", "Bengali", "\u0980", "\u09ff"),
    ("Punjabi", "Gurmukhi", "\u0a00", "\u0a7f"),
    ("Gujarati", "Gujarati", "\u0a80", "\u0aff"),
    ("Odia", "Odia", "\u0b00", "\u0b7f"),
    ("Tamil", "Tamil", "\u0b80", "\u0bff"),
    ("Telugu", "Telugu", "\u0c00", "\u0c7f"),
    ("Kannada", "Kannada", "\u0c80", "\u0cff"),
    ("Malayalam", "Malayalam", "\u0d00", "\u0d7f"),
    ("Arabic / Urdu", "Arabic", "\u0600", "\u06ff"),
]
# Common words in romanised Hindi ("Hinglish"), which the rules partly understand.
_HINGLISH = {"hai", "hain", "kya", "nahi", "nahin", "aap", "aapka", "aapke", "karo", "karein", "kijiye",
             "mera", "meri", "tum", "tumhara", "bhai", "paisa", "paise", "jaldi", "abhi", "bhejo",
             "bhej", "kar", "raha", "rahi", "hoga", "jayega", "jaega", "band", "khata", "turant", "ji", "beta"}


@dataclass(frozen=True)
class Language:
    name: str
    script: str
    supported: bool   # can the rules and model read it reliably?

    def to_dict(self) -> dict:
        return {"name": self.name, "script": self.script, "supported_by_detector": self.supported}


def detect_language(text: str) -> Language:
    letters = [ch for ch in text if ch.isalpha()]
    if not letters:
        return Language("Unknown", "none", False)
    counts = {}
    for ch in letters:
        if ch.isascii():
            counts["Latin"] = counts.get("Latin", 0) + 1
            continue
        for name, script, lo, hi in _SCRIPTS:
            if lo <= ch <= hi:
                counts[name] = counts.get(name, 0) + 1
                break
        else:
            counts["Other"] = counts.get("Other", 0) + 1
    top, n = max(counts.items(), key=lambda kv: kv[1])
    if top == "Latin" and n / len(letters) >= 0.5:
        words = _LATIN_WORD.findall(text.lower())
        hinglish = sum(w in _HINGLISH for w in words)
        if words and hinglish >= 2 and hinglish / len(words) >= 0.15:
            return Language("Hinglish (romanised Hindi)", "Latin", True)
        return Language("English", "Latin", True)
    if top == "Other":
        return Language("Other", "Other", False)
    script = next(s for name, s, *_ in _SCRIPTS if name == top)
    return Language(top, script, False)


# --- conversations ---------------------------------------------------------------------
@dataclass(frozen=True)
class Turn:
    speaker: str
    text: str


# WhatsApp exports: "12/10/24, 10:42 pm - Name: text" and "[12/10/24, 10:42:13 PM] Name: text"
_WHATSAPP = re.compile(
    r"^\[?\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4},?\s+\d{1,2}:\d{2}(?::\d{2})?\s*(?:[ap]\.?m\.?)?\]?\s*(?:-\s*)?"
    r"(?P<speaker>[^:]{1,40}):\s(?P<text>.*)$", re.I)
# Simple "Name: text" lines. The name must be short and not look like a URL or time.
_SIMPLE = re.compile(r"^(?P<speaker>[^\s:/][^:/]{0,24}?):\s+(?P<text>\S.*)$")
_NOT_A_SPEAKER = re.compile(r"^(https?|www|http|note|ps|re|fwd|subject|to|from|date|otp|dear \w+)$", re.I)
_SYSTEM_LINE = re.compile(r"(messages and calls are end-to-end encrypted|<media omitted>|this message was deleted)", re.I)


def parse_conversation(text: str) -> list[Turn] | None:
    """Split text into speaker turns, or None if it isn't a conversation."""
    lines = [ln for ln in text.split("\n") if ln.strip()]
    if len(lines) < 2:
        return None
    turns: list[Turn] = []
    for pattern in (_WHATSAPP, _SIMPLE):
        turns = []
        for ln in lines:
            m = pattern.match(ln.strip())
            speaker = m.group("speaker").strip() if m else ""
            if m and not _NOT_A_SPEAKER.match(speaker) and not speaker[:1].isdigit():
                if not _SYSTEM_LINE.search(m.group("text")):
                    turns.append(Turn(speaker, m.group("text").strip()))
            elif turns:  # a message that continues over several lines
                turns[-1] = Turn(turns[-1].speaker, turns[-1].text + "\n" + ln.strip())
        speakers = {t.speaker.lower() for t in turns}
        if len(turns) >= 2 and len(speakers) >= 2:
            return turns
    return None


_ME = {"you", "me", "myself", "i"}


def user_speaker(turns: list[Turn]) -> str | None:
    """The person checking the chat, if the export marks them ("You", "Me")."""
    for t in turns:
        if t.speaker.lower() in _ME:
            return t.speaker
    return None
