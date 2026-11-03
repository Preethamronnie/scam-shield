"""Context engine: patterns that only show up across a conversation.

Some scams look harmless one message at a time. "Hi, is this Ananya?" is
fine on its own; the same chat ending in "my mentor can double your money"
is a classic slow-build (pig-butchering) scam. This module runs the
message-level rules on every turn, then looks for patterns across turns.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .preprocess import Turn, user_speaker
from .risk import CATEGORY_OF
from .signals import Signal, find_signals

SERIOUS = {"credential_theft", "financial_manipulation", "impersonation"}
# Personal small talk, not just "hello": a business greeting ("Hello sir, I am
# from customer care") isn't trust-building in the slow-build sense.
_RAPPORT = re.compile(
    r"\b(how are you|nice to (meet|chat|talk)|where are you from|you seem (nice|kind|sweet|interesting)|"
    r"sorry,? (wrong number|i (think )?(have|got) the wrong)|is this \w+('s)?( number)?\?|what do you do|"
    r"are you (married|single)|i (work|live) in|my (uncle|aunt|cousin|friend|mentor))\b", re.I)
_BUSINESS = re.compile(r"\b(customer care|refund|account|bank|order|kyc|parcel|delivery|officer|department|sir|madam)\b", re.I)
_REFUSAL = re.compile(r"\b(no|nope|not interested|i (won'?t|will not|don'?t want)|stop|leave me|"
                      r"i'?m not (sharing|sending|paying)|not sharing|not sending|not paying|block(ing)? you)\b", re.I)


@dataclass
class TurnFinding:
    index: int
    speaker: str
    signals: list[Signal]

    def categories(self) -> set[str]:
        return {c for s in self.signals for c in CATEGORY_OF.get(s.id, ())}

    @property
    def flagged(self) -> bool:
        """A clear red flag in this message (not just a faint sign like the word 'today')."""
        return any(s.strength >= 0.5 for s in self.signals)


@dataclass
class ConversationAnalysis:
    turns: list[Turn]
    per_turn: list[TurnFinding]
    signals: list[Signal]                 # per-turn signals (strongest of each) + conversation patterns
    findings: list[str] = field(default_factory=list)   # plain-language conversation-level findings
    user: str | None = None

    @property
    def span_days(self) -> int | None:
        days = [t.day for t in self.turns if t.day]
        return (max(days) - min(days)).days if len(days) >= 2 else None

    @property
    def first_suspicious(self) -> int | None:
        """Index of the first message with a clear red flag."""
        return next((f.index for f in self.per_turn if f.flagged), None)

    def to_dict(self) -> dict:
        return {
            "first_suspicious_message": None if self.first_suspicious is None else self.first_suspicious + 1,
            "timeline": [
                {"message_number": f.index + 1, "from": f.speaker, "text": t.text, "when": t.when,
                 "is_user": bool(self.user) and f.speaker == self.user,
                 "red_flags": list(dict.fromkeys(s.reason for s in f.signals if s.strength >= 0.5))}
                for f, t in zip(self.per_turn, self.turns)],
            "messages": len(self.turns),
            "time_span_days": self.span_days,
            "people": sorted({t.speaker for t in self.turns}),
            "user_identified_as": self.user,
            "conversation_findings": self.findings,
            "messages_with_red_flags": [
                {"message_number": f.index + 1, "from": f.speaker, "red_flags": [s.id for s in f.signals]}
                for f in self.per_turn if f.signals],
        }


def analyze_conversation(turns: list[Turn], online: bool = False) -> ConversationAnalysis:
    me = user_speaker(turns)
    per_turn = []
    for i, t in enumerate(turns):
        # The user's own messages aren't evidence against the other person.
        sigs = [] if (me and t.speaker == me) else find_signals(t.text, online)
        per_turn.append(TurnFinding(i, t.speaker, sigs))

    # Keep the strongest instance of each rule across the conversation.
    best: dict[str, Signal] = {}
    for f in per_turn:
        for s in f.signals:
            if s.id not in best or s.strength > best[s.id].strength:
                best[s.id] = s
    signals = list(best.values())
    findings: list[str] = []
    n = len(turns)

    # 1. Slow build: an early friendly / rapport phase, then money or credential requests later.
    first_serious = next((f for f in per_turn if f.categories() & SERIOUS), None)
    if first_serious is not None and first_serious.index >= 2:
        early = turns[: first_serious.index]
        early_rapport = sum(bool(_RAPPORT.search(t.text)) and not _BUSINESS.search(t.text)
                            for t in early if t.speaker == first_serious.speaker)
        if early_rapport >= 1:
            s = max(first_serious.signals, key=lambda x: x.strength)
            signals.append(Signal(
                "slow_build", 0.85,
                "The chat starts friendly and only later turns to money, codes or investments. "
                "Scammers build trust first so the request feels normal.", s.phrase, origin="context"))
            first_day, ask_day = turns[0].day, turns[first_serious.index].day
            span = (ask_day - first_day).days if first_day and ask_day else None
            over = f" over {span} days" if span and span > 0 else ""
            findings.append(f"Friendly chat for {first_serious.index} messages{over}, then {first_serious.speaker} "
                            f"turned to money or personal details in message {first_serious.index + 1}.")

    # 2. Repeated pressure: urgency or threats in two or more messages from the same person.
    #    Only counts for someone who also asks for money, codes or details:
    #    a colleague saying "urgent" twice about a deadline is just work.
    pressure: dict[str, int] = {}
    askers = {f.speaker for f in per_turn if f.categories() & SERIOUS}
    for f in per_turn:
        if "urgency" in f.categories():
            pressure[f.speaker] = pressure.get(f.speaker, 0) + 1
    for speaker, count in pressure.items():
        if count >= 2 and speaker in askers:
            signals.append(Signal("repeated_pressure", 0.75,
                                  f"{speaker} keeps pushing you to hurry or threatening consequences, "
                                  "message after message.", "", origin="context"))
            findings.append(f"{speaker} applied pressure in {count} separate messages.")
            break

    # 3. Ignoring a refusal: after a serious request, someone says no, and the
    #    other person keeps asking. ("No, wrong number" at the start doesn't count.)
    for i, t in enumerate(turns[:-1]):
        asked_before = any(f.categories() & SERIOUS and f.speaker != t.speaker for f in per_turn[:i])
        if asked_before and _REFUSAL.search(t.text):
            later = [f for f in per_turn[i + 1:] if f.speaker != t.speaker and f.categories() & SERIOUS]
            if later:
                signals.append(Signal("ignores_refusal", 0.7,
                                      f"After {t.speaker} said no, {later[0].speaker} kept asking. "
                                      "Genuine companies and friends accept a no.", "", origin="context"))
                findings.append(f"{later[0].speaker} kept asking after {t.speaker} refused "
                                f"(message {i + 1}).")
                break

    # 4. A "wrong number" style opener that never turns into any request is just
    #    a normal chat: in a longer conversation it stops counting as evidence.
    if n >= 4 and not any(f.categories() & SERIOUS for f in per_turn):
        if any(s.id == "wrong_number_opener" for s in signals):
            signals = [s for s in signals if s.id != "wrong_number_opener"]
            findings.append("It starts like a 'wrong number' message, but no requests for money, codes "
                            "or details followed.")

    # 5. Several different serious tactics spread across the chat.
    serious_turns = [f for f in per_turn if f.categories() & SERIOUS]
    if len({f.index for f in serious_turns}) >= 3 and n >= 4:
        findings.append(f"Red flags appear in {len(serious_turns)} separate messages, not just one.")

    return ConversationAnalysis(turns, per_turn, signals, findings, me)
