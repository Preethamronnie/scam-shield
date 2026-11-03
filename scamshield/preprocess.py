"""Preprocessing: clean the text, detect its language, and split conversations.

Everything downstream (rules, model, context engine) gets the same cleaned
text, so a scam can't dodge the rules with invisible characters or
look-alike letters.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import date

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
# Common words in romanised Indian languages. Words that are also common in English
# ("do", "to", "main", "me", "hi", "he") are left out to avoid false matches.
_ROMANISED = {
    "Hindi": {"hai", "hain", "kya", "nahi", "nahin", "aap", "aapka", "aapke", "aapko", "karo", "karein", "kijiye",
              "mera", "meri", "mujhe", "tum", "tumhara", "tumhe", "bhai", "paisa", "paise", "jaldi", "abhi", "bhejo",
              "bhej", "kar", "raha", "rahi", "rahe", "hoga", "jayega", "jaega", "khata", "turant", "beta", "kal",
              "aaj", "shaam", "subah", "raat", "ghar", "jaana", "jana", "khana", "banaya", "gaya", "gayi", "kiya",
              "dena", "lena", "liye", "bhi", "toh", "accha", "achha", "theek", "thik", "haan", "yaar", "didi",
              "bhaiya", "mummy", "papa", "kaise", "kaisa", "kab", "kahan", "mein", "ke", "ki", "ka", "ko", "se",
              "ne", "batao", "batana", "dungi", "dunga", "wapas", "galti", "ho", "kuch", "sab", "bas", "phir"},
    "Tamil": {"unga", "ungal", "enna", "panna", "pannunga", "vanakkam", "illa", "illai", "seri", "romba", "konjam",
              "inniki", "naan", "neenga", "eppo", "enga", "sollunga", "anuppunga", "vendam", "irukku"},
    "Telugu": {"meeru", "mee", "cheyandi", "ledu", "undi", "kavali", "emi", "enti", "nenu", "chala", "baagundi",
               "pampandi", "cheppandi", "ippudu", "ekkada", "vaddu", "ivvandi"},
    "Kannada": {"neevu", "nimma", "maadi", "beku", "enu", "naanu", "hegide", "illi", "alli", "kodi", "kalisi",
                "beda", "swalpa", "haudu", "gottu"},
    "Malayalam": {"ningal", "ningalude", "cheyyuka", "alle", "venam", "enthu", "njan", "evide", "ippol",
                  "ayakkuka", "parayu", "kollam", "sheri", "vendaa", "undo"},
}
# Indian-script letters that the detector covers through lexicon.py (Hindi only, partially).
_PARTIAL_SCRIPTS = {"Devanagari"}


@dataclass(frozen=True)
class Language:
    name: str
    script: str
    coverage: str            # "full" (English), "partial" (Hindi scam phrases), or "none"
    mix: tuple = ()          # (("Latin", 0.6), ("Devanagari", 0.4)) for mixed-script text
    romanised: bool = False  # an Indian language written in English letters

    @property
    def supported(self) -> bool:
        return self.coverage != "none"

    def to_dict(self) -> dict:
        return {"name": self.name, "script": self.script, "detector_coverage": self.coverage,
                "script_mix": {k: round(v, 2) for k, v in self.mix}, "romanised_indian_language": self.romanised}

    def coverage_note(self) -> str:
        if self.coverage == "full":
            return ""
        if self.coverage == "partial":
            return (f"The message is in {self.name}. The detector recognises common Hindi scam phrases, "
                    "not Hindi in general, so it may miss scams worded in other ways.")
        return (f"The message is in {self.name}, which the detector can't read yet. Only English words in it "
                "(like OTP, KYC or links) were checked.")


def _romanised_language(text: str) -> tuple[str, float] | None:
    words = _LATIN_WORD.findall(text.lower())
    if not words:
        return None
    scores = {lang: sum(w in vocab for w in words) for lang, vocab in _ROMANISED.items()}
    lang, hits = max(scores.items(), key=lambda kv: kv[1])
    if hits >= 2 and hits / len(words) >= 0.15:
        return lang, hits / len(words)
    return None


def detect_language(text: str) -> Language:
    """Which language and script the text is in, how mixed it is, and how well
    the detector covers it. Coverage is about *detection*: an explanation can be
    shown in any of 8 languages, but that doesn't mean the rules can read them."""
    letters = [ch for ch in text if ch.isalpha()]
    if not letters:
        return Language("Unknown", "none", "none")
    counts: dict[str, int] = {}
    for ch in letters:
        if ch.isascii():
            key = "Latin"
        else:
            key = next((script for _n, script, lo, hi in _SCRIPTS if lo <= ch <= hi), "Other")
        counts[key] = counts.get(key, 0) + 1
    shares = sorted(((k, v / len(letters)) for k, v in counts.items()), key=lambda kv: -kv[1])
    mix = tuple((k, v) for k, v in shares if v >= 0.1)
    top, share = shares[0]

    if top == "Latin" and share >= 0.5:
        rom = _romanised_language(text)
        native = next(((k, v) for k, v in mix if k != "Latin"), None)
        if rom and rom[0] == "Hindi":
            name = "Hinglish (romanised Hindi)"
            return Language(name, "Latin", "partial", mix, True)
        if rom:
            return Language(f"{rom[0]} written in English letters", "Latin", "none", mix, True)
        if native:
            lang = next(n for n, s_, *_ in _SCRIPTS if s_ == native[0]) if native[0] != "Other" else "another language"
            # A sizeable part isn't English, so coverage is only partial.
            return Language(f"English with {lang}", "Latin", "partial" if native[1] >= 0.3 else "full", mix)
        return Language("English", "Latin", "full", mix)
    if top == "Other":
        return Language("Other", "Other", "none", mix)
    name = next(n for n, s_, *_ in _SCRIPTS if s_ == top)
    coverage = "partial" if top in _PARTIAL_SCRIPTS else "none"
    if any(k == "Latin" and v >= 0.2 for k, v in mix):
        name = f"{name} mixed with English"
    return Language(name, top, coverage, mix)


# --- conversations ---------------------------------------------------------------------
@dataclass(frozen=True)
class Turn:
    speaker: str
    text: str
    when: str = ""                 # date and time as written in a WhatsApp export, e.g. "12/10/24, 10:42 pm"
    day: date | None = None        # the date, when it could be read

    def to_dict(self) -> dict:
        return {"from": self.speaker, "text": self.text, "when": self.when}


# WhatsApp exports: "12/10/24, 10:42 pm - Name: text" and "[12/10/24, 10:42:13 PM] Name: text"
_WHATSAPP = re.compile(
    r"^\[?(?P<date>\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}),?\s+(?P<time>\d{1,2}:\d{2}(?::\d{2})?\s*(?:[ap]\.?m\.?)?)\]?\s*(?:-\s*)?"
    r"(?P<speaker>[^:]{1,40}):\s(?P<text>.*)$", re.I)


def _parse_day(value: str):
    """WhatsApp dates in India are day/month/year; fall back to month/day if that's impossible."""
    parts = [int(x) for x in re.split(r"[/.-]", value)]
    if len(parts) != 3:
        return None
    d, m, y = parts
    y += 2000 if y < 100 else 0
    for day, month in ((d, m), (m, d)):
        try:
            return date(y, month, day)
        except ValueError:
            continue
    return None
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
                    stamp = m.groupdict().get("date")
                    when = f"{stamp}, {m.group('time').strip()}" if stamp else ""
                    turns.append(Turn(speaker, m.group("text").strip(), when, _parse_day(stamp) if stamp else None))
            elif turns:  # a message that continues over several lines
                t = turns[-1]
                turns[-1] = Turn(t.speaker, t.text + "\n" + ln.strip(), t.when, t.day)
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
