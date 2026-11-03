"""Jagratha Circle: ask a family member before acting.

In many Indian families, elders check with their children (and children with
their parents) before doing anything with money. This builds a short message
with the verdict and the red flags, ready to send on WhatsApp or SMS to
whoever the user picks in their own contacts.

Privacy and safety:
  * Nothing is stored or sent by the server. The message is opened in the
    user's own WhatsApp or SMS app, and they choose who it goes to.
  * Links are "defanged" (sbi-kyc[.]example[.]xyz) so a relative can't open the
    scam link by tapping it.
  * The user's own private details (OTPs, account, card, Aadhaar and PAN
    numbers) are masked. The scammer's phone number and UPI ID are kept, since
    the family needs them to judge, block or report.
"""
from __future__ import annotations

import re
from urllib.parse import quote

from . import i18n
from .privacy import Masker
from .risk import CAREFUL, SCAM, UNSURE

_PRIVATE_KINDS = {"CODE", "ACCOUNT", "CARD", "AADHAAR", "PAN"}
_URL = re.compile(r"\b(?:https?://)?(?:www\.)?[\w-]+(?:\.[\w-]+)+(?:/[^\s]*)?", re.I)


def defang(text: str) -> str:
    """Make links unclickable but still readable: https://a.b/c -> hxxps://a[.]b/c"""
    def fix(m: re.Match) -> str:
        url = m.group(0)
        s, e = m.start(), m.end()
        if (s > 0 and text[s - 1] == "@") or (e < len(text) and text[e] == "@"):
            return url  # part of a UPI ID or email address, not a tappable link
        if "." not in url or url.replace(".", "").isdigit() and not url.count(".") == 3:
            return url  # amounts like 1,250.50
        url = re.sub(r"^http", "hxxp", url, flags=re.I)
        return url.replace(".", "[.]")
    return _URL.sub(fix, text)


def mask_private(text: str) -> str:
    """Mask the user's own sensitive numbers, keep phone numbers and UPI IDs."""
    m = Masker()
    masked = m.mask(text)
    for ph, original in m.mapping.items():
        kind = ph.strip("[]").rsplit("_", 1)[0]
        if kind not in _PRIVATE_KINDS:
            masked = masked.replace(ph, original)
        else:
            masked = masked.replace(ph, "[hidden]")
    return masked


def family_message(result, language: str = "English", app_url: str | None = None, max_flags: int = 3) -> str:
    """Short, plain message for a family member."""
    rep = result.report
    lines = [i18n.phrase("family_help", language)]
    if language != "English":
        lines.append(i18n.phrase("family_help", "English"))
    lines.append("")
    verdict = f"Jagratha says: {result.verdict.upper()}"
    if result.verdict in (SCAM, CAREFUL) and rep.scam_types:
        verdict += f" ({rep.scam_types[0]})"
    lines.append(verdict)
    if rep.impersonated_organisation:
        lines.append(f"Pretending to be: {rep.impersonated_organisation}")
    if rep.harm.get("level") == "Severe" and result.verdict in (SCAM, CAREFUL):
        lines.append("What's at stake: " + rep.harm["at_stake"])
    if rep.intents:
        wants = [it["action"] + (f" ({it['detail']})" if it["detail"] else "") for it in rep.intents[:2]]
        lines.append("They want me to: " + defang("; ".join(wants)))
    flags = [c for c in result.categories if c.present and c.category.key != "scam_wording"]
    reasons = list(dict.fromkeys(s.reason for c in flags for s in c.signals))[:max_flags]
    if reasons:
        lines.append("Warning signs:")
        lines += [f"- {defang(r)}" for r in reasons]
    # Whole sentences only (a bare link is already covered by the warning signs).
    quotes = [p["phrase"] for p in rep.suspicious_phrases if len(p["phrase"].split()) >= 3][:2]
    if quotes:
        lines.append("The message says:")
        lines += [f'"{defang(mask_private(q))}"' for q in quotes]
    contacts = [p.number for p in rep.phone_numbers] + rep.payment_ids
    if contacts and result.verdict in (SCAM, CAREFUL, UNSURE):
        lines.append("Contact details in it: " + ", ".join(contacts[:3]))
    if app_url:
        lines += ["", f"Checked with Jagratha: {app_url}"]
    return "\n".join(lines)


def call_alert(language: str = "English", app_url: str | None = None) -> str:
    """The message to send during a suspicious call."""
    lines = [i18n.phrase("family_help", language)]
    if language != "English":
        lines.append(i18n.phrase("family_help", "English"))
    lines.append("I'm on a call with someone who may be a scammer. If I don't answer, please keep trying.")
    if app_url:
        lines += ["", f"Jagratha: {app_url}"]
    return "\n".join(lines)


def whatsapp_link(text: str) -> str:
    """Opens WhatsApp with the message ready; the user picks the contact."""
    return "https://wa.me/?text=" + quote(text)


def sms_link(text: str) -> str:
    return "sms:?&body=" + quote(text)
