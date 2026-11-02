"""Complaint kit: turn what happened into ready-to-file text.

Victims often lose the most valuable hours not knowing what to write. From a
few answers (and the details Jagratha already extracted from the message),
this builds:
  1. a complaint summary to paste into cybercrime.gov.in (or read out on 1930),
  2. a request to the user's bank or payment app to block the transaction and
     raise a fraud dispute,
  3. a checklist of evidence to keep.

Nothing is stored or sent anywhere: the text is shown to the user and can be
downloaded as plain text or as a print-ready web page (which, unlike a basic
PDF, displays Indian scripts using the phone's own fonts and can be saved as
PDF from the browser).
"""
from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import date, time

CONTACT_METHODS = ["Phone call", "Video call", "SMS", "WhatsApp", "Telegram", "Instagram / Facebook",
                   "Email", "Website / app", "Other"]
PAYMENT_METHODS = ["UPI (GPay, PhonePe, Paytm, etc.)", "Bank transfer (NEFT / IMPS / RTGS)", "Debit or credit card",
                   "Wallet", "Gift card or voucher", "Cash deposit", "Cryptocurrency", "Other"]

# Closest options on the national portal's financial-fraud form. Wording on the
# portal can change, so the kit says "choose the closest option".
_PORTAL_SUBCATEGORY = {
    "UPI (GPay, PhonePe, Paytm, etc.)": "UPI related fraud",
    "Bank transfer (NEFT / IMPS / RTGS)": "Internet banking related fraud",
    "Debit or credit card": "Debit / credit card fraud",
    "Wallet": "E-wallet related fraud",
}


@dataclass
class Incident:
    happened: list[str]                 # keys from emergency.SITUATIONS
    when_date: date | None = None
    when_time: time | None = None
    contact_method: str = ""
    claimed_to_be: str = ""             # organisation or person they pretended to be
    scam_type: str = ""
    amount: float = 0.0
    payment_method: str = ""
    transaction_ids: list[str] = field(default_factory=list)   # UTR / transaction IDs
    user_bank: str = ""                 # the user's own bank or payment app
    suspect_phones: list[str] = field(default_factory=list)
    suspect_payment_ids: list[str] = field(default_factory=list)   # UPI IDs, account numbers they gave
    suspect_links: list[str] = field(default_factory=list)
    suspect_other: list[str] = field(default_factory=list)          # emails, profile names, app names
    description: str = ""


def from_report(report) -> dict:
    """Pre-fill suspect details from a Jagratha evidence report."""
    if report is None:
        return {}
    return {
        "claimed_to_be": report.impersonated_organisation or (report.claimed_organisations[0]
                                                              if report.claimed_organisations else ""),
        "scam_type": report.scam_types[0] if report.scam_types else "",
        "suspect_phones": [p.number for p in report.phone_numbers],
        "suspect_payment_ids": list(report.payment_ids),
        "suspect_links": [u.url for u in report.urls if u.assessment != "official"],
        "suspect_other": list(report.emails),
    }


def _when(i: Incident) -> str:
    if not i.when_date:
        return "date not given"
    s = i.when_date.strftime("%d %B %Y")
    return s + (f" at about {i.when_time.strftime('%I:%M %p').lstrip('0')}" if i.when_time else "")


def _money(amount: float) -> str:
    whole = f"{amount:,.2f}".rstrip("0").rstrip(".")
    return f"Rs {whole}"


def portal_category(i: Incident) -> str:
    if i.amount > 0 or "paid" in i.happened:
        sub = _PORTAL_SUBCATEGORY.get(i.payment_method, "the closest option to how you paid")
        return f"Online Financial Fraud, then {sub}"
    if "threat" in i.happened:
        return "the closest option for blackmail or harassment (if it involves women or children, " \
               "use the section for crimes against women and children)"
    return "the closest option under other cyber crime"


def complaint_text(i: Incident) -> str:
    lines = ["CYBER FRAUD COMPLAINT SUMMARY", ""]
    what = []
    if "paid" in i.happened or i.amount > 0:
        what.append(f"I lost {_money(i.amount)}" if i.amount > 0 else "I sent money")
    if "otp" in i.happened:
        what.append("I shared an OTP / PIN / password or card details")
    if "app" in i.happened:
        what.append("I installed an app or gave screen access")
    if "id" in i.happened:
        what.append("I shared ID documents (Aadhaar / PAN)")
    if "threat" in i.happened:
        what.append("I am being threatened / blackmailed")
    lines.append("What happened: " + ("; ".join(what) if what else "I was targeted by a scam") + ".")
    lines.append(f"When: {_when(i)}.")
    if i.contact_method:
        lines.append(f"How they contacted me: {i.contact_method}.")
    if i.claimed_to_be:
        lines.append(f"They pretended to be: {i.claimed_to_be}.")
    if i.scam_type:
        lines.append(f"Type of scam: {i.scam_type}.")
    lines.append("")
    if i.description.strip():
        lines += ["In my own words:", i.description.strip(), ""]

    if i.amount > 0 or i.transaction_ids:
        lines.append("Transaction details:")
        if i.amount > 0:
            lines.append(f"- Amount: {_money(i.amount)}")
        if i.payment_method:
            lines.append(f"- Paid by: {i.payment_method}")
        if i.user_bank:
            lines.append(f"- From my bank / app: {i.user_bank}")
        for t in i.transaction_ids:
            lines.append(f"- Transaction ID / UTR: {t}")
        lines.append("")

    suspect = ([f"- Phone number: {p}" for p in i.suspect_phones]
               + [f"- UPI ID / account they gave: {p}" for p in i.suspect_payment_ids]
               + [f"- Website / link: {u}" for u in i.suspect_links]
               + [f"- Other: {o}" for o in i.suspect_other])
    if suspect:
        lines += ["Details of the scammer:"] + suspect + [""]
    lines.append("I request that the transaction be traced and the receiving account(s) frozen, "
                 "and that the people responsible be investigated.")
    return "\n".join(lines)


def bank_request(i: Incident) -> str:
    bank = i.user_bank or "my bank"
    lines = ["Subject: URGENT: Fraudulent transaction, please block and raise a dispute", "",
             f"Dear {bank} team,", "",
             f"I am a victim of a cyber fraud on {_when(i)}."]
    if i.amount > 0:
        lines.append(f"{_money(i.amount)} was transferred from my account"
                     + (f" by {i.payment_method}" if i.payment_method else "") + " because of the fraud.")
    for t in i.transaction_ids:
        lines.append(f"Transaction ID / UTR: {t}")
    if i.suspect_payment_ids:
        lines.append("The money went to: " + ", ".join(i.suspect_payment_ids) + ".")
    lines += ["", "Please, urgently:",
              "1. Block any further debits from my account, card and UPI.",
              "2. Raise a fraud dispute for the transaction(s) above.",
              "3. Contact the receiving bank to freeze the money (put a lien on the receiving account).",
              "4. Send me the complaint / dispute reference number.", "",
              "I have reported this on the National Cyber Crime Helpline (1930) / cybercrime.gov.in. "
              "Complaint number: ____________", "",
              "Account / card (last 4 digits only): ________", "Name: ____________", "Phone: ____________"]
    return "\n".join(lines)


def evidence_checklist(i: Incident) -> list[str]:
    items = ["Screenshots of the whole chat or the messages (don't delete them)",
             "The scammer's phone number, profile name or website, as shown on your screen"]
    if i.amount > 0 or "paid" in i.happened:
        items += ["Transaction ID / UTR number for every payment (in your bank or UPI app's payment history)",
                  "Bank SMS or email confirming each payment"]
    if "app" in i.happened:
        items.append("The name of the app you installed (before uninstalling it, take a screenshot)")
    if "threat" in i.happened:
        items.append("Screenshots of the threats and the account or number sending them")
    items.append("The complaint number from 1930 / cybercrime.gov.in, and from your bank")
    return items


def as_text(i: Incident) -> str:
    return "\n".join([complaint_text(i), "", "-" * 60, "", "REQUEST TO MY BANK", "", bank_request(i), "",
                      "-" * 60, "", "EVIDENCE TO KEEP"] + [f"[ ] {x}" for x in evidence_checklist(i)]
                     + ["", f"On cybercrime.gov.in, choose: {portal_category(i)}."])


def as_html(i: Incident) -> str:
    """A print-ready page. Opens on any phone; 'Print > Save as PDF' makes a PDF."""
    def block(title: str, text: str) -> str:
        return f"<h2>{html.escape(title)}</h2><pre>{html.escape(text)}</pre>"
    checklist = "".join(f"<li>{html.escape(x)}</li>" for x in evidence_checklist(i))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cyber fraud complaint kit</title>
<style>
 body {{ font-family: system-ui, sans-serif; max-width: 760px; margin: 2rem auto; padding: 0 1rem; color: #101828; }}
 h1 {{ font-size: 1.5rem; }} h2 {{ font-size: 1.15rem; margin-top: 2rem; }}
 pre {{ white-space: pre-wrap; font-family: inherit; background: #f2f4f7; padding: 1rem; border-radius: 8px; }}
 .call {{ background: #b42318; color: #fff; padding: 1rem; border-radius: 8px; font-weight: 600; }}
 @media print {{ .call {{ color: #000; background: none; border: 2px solid #000; }} }}
</style></head><body>
<h1>Cyber fraud complaint kit</h1>
<p class="call">Call 1930 (National Cyber Crime Helpline) and report at cybercrime.gov.in as soon as possible.
On the portal, choose: {html.escape(portal_category(i))}.</p>
{block("1. Complaint summary (paste into cybercrime.gov.in)", complaint_text(i))}
{block("2. Request to your bank or payment app", bank_request(i))}
<h2>3. Evidence to keep</h2><ul>{checklist}</ul>
<p><small>Made with Jagratha. Nothing you entered was stored.</small></p>
</body></html>"""
