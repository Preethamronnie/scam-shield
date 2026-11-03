"""Routes each input to the detectors that are relevant to it.

Not every detector needs to run for every input: a plain SMS doesn't need
the APK scanner, and a message with no links doesn't need URL intelligence.
The router decides, and records what ran and why, so the evidence report
shows exactly which checks were applied.

(Every local detector takes a few milliseconds, so routing here is about
clarity and avoiding irrelevant findings more than speed; it would matter
more as heavier detectors, such as audio analysis, are added.)
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Module:
    name: str
    ran: bool
    why: str

    def to_dict(self) -> dict:
        return {"module": self.name, "ran": self.ran, "why": self.why}


def plan(*, has_links: bool, is_conversation: bool, payment_terms: bool, has_contacts: bool,
         file_types: list[str], has_media: bool = False) -> list[Module]:
    images = any(t == "Image" for t in file_types)
    docs = [t for t in file_types if t != "Image"]
    return [
        Module("Rule engine", True, "always: known scam tactics in English, Hindi and Hinglish"),
        Module("Intent detector", True, "always: what the message wants you to do"),
        Module("Manipulation detector", True, "always: how it pressures you"),
        Module("ML model", True, "always: corroborating evidence"),
        Module("Entity extraction", True, "always: numbers, payment IDs, organisations"),
        Module("URL intelligence", has_links, "links found" if has_links else "no links in the message"),
        Module("Context engine", is_conversation,
               "conversation detected" if is_conversation else "single message, not a conversation"),
        Module("Payment detector", payment_terms or images,
               "payment words or images found" if (payment_terms or images) else "no payment words"),
        Module("Identity intelligence", has_contacts,
               "phone numbers, emails or payment IDs found" if has_contacts else "no contact or payment details"),
        Module("Attachment scanner", bool(docs), ", ".join(docs) if docs else "no PDF, email or app files"),
        Module("Voice and media", has_media, "audio or video added" if has_media else "no audio or video"),
    ]
