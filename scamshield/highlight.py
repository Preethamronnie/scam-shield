"""Highlighting the exact sentences that raised a red flag.

Turns the evidence into a copy of the message with the suspicious parts
marked and numbered, plus a numbered list explaining each one. Pure
functions (no Streamlit) so they can be tested.
"""
from __future__ import annotations

import html
import re
from dataclasses import dataclass, field

from .risk import CRITICAL, HIGH, MEDIUM, CategoryEvidence

COLORS = {CRITICAL: "#fda29b", HIGH: "#fec84b", MEDIUM: "#fef0c7"}   # light backgrounds, dark text in both themes
LEVEL_RANK = {CRITICAL: 0, HIGH: 1, MEDIUM: 2}


@dataclass
class Mark:
    start: int
    end: int
    level: str
    numbers: list[int] = field(default_factory=list)


@dataclass
class Note:
    number: int
    phrase: str
    reason: str
    category: str
    level: str


def find_marks(text: str, categories: list[CategoryEvidence]) -> tuple[list[Mark], list[Note]]:
    """Locate each quoted phrase in the text. Most dangerous first, so when two
    findings point at the same words, the mark gets the more serious colour."""
    found = []
    for c in categories:
        if not c.present or c.category.key == "scam_wording":
            continue
        for s in c.signals:
            if s.phrase:
                found.append((LEVEL_RANK[c.category.level], -s.strength, s, c))
    found.sort(key=lambda f: (f[0], f[1]))

    marks: list[Mark] = []
    notes: list[Note] = []
    seen_reasons: set[str] = set()
    for _, _, s, c in found:
        if s.reason in seen_reasons:
            continue
        seen_reasons.add(s.reason)
        needle = (s.context or s.phrase).strip("…").strip()
        # Rules see the text with line breaks collapsed, so match any whitespace.
        m = re.search(r"\s+".join(map(re.escape, needle.split())), text, re.I) if needle else None
        number = len(notes) + 1
        notes.append(Note(number, s.phrase, s.reason, c.category.name, c.category.level))
        if not m:
            continue  # explained in the list, just not highlighted
        start, end = m.start(), m.end()
        overlap = next((m for m in marks if start < m.end and m.start < end), None)
        if overlap:
            overlap.numbers.append(number)
        else:
            marks.append(Mark(start, end, c.category.level, [number]))
    return sorted(marks, key=lambda m: m.start), notes


def highlighted_html(text: str, marks: list[Mark]) -> str:
    """The message as safe HTML, with suspicious parts highlighted and numbered."""
    out, pos = [], 0
    for m in marks:
        out.append(html.escape(text[pos:m.start]))
        nums = ",".join(str(n) for n in m.numbers)
        out.append(f'<mark style="background:{COLORS[m.level]};color:#101828;border-radius:4px;padding:0 2px">'
                   f'{html.escape(text[m.start:m.end])}<sup style="font-weight:700">&nbsp;{nums}</sup></mark>')
        pos = m.end
    out.append(html.escape(text[pos:]))
    return "".join(out).replace("\n", "<br>")
