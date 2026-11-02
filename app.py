"""Jagratha web app. Run with:  streamlit run app.py"""
import html
import json

import streamlit as st
from dotenv import load_dotenv

from datetime import date
from urllib.parse import urlsplit

from scamshield import (circle, complaint, education, emergency, feedback, i18n, ocr, oncall, redirects,
                        reputation, safety, telemetry)
from scamshield import explain as llm
from scamshield import model as ml
from scamshield.analyzer import CAREFUL, SAFE, SCAM, UNSURE, check
from scamshield.highlight import find_marks, highlighted_html
from scamshield.links import inspect_link
from scamshield.risk import CRITICAL, HIGH, MEDIUM

load_dotenv()
st.set_page_config(page_title="Jagratha · Check before you trust", page_icon="🪔", layout="centered")

STYLE = {
    SCAM: ("#b42318", "#fef3f2", "🚫"),
    CAREFUL: ("#93370d", "#fffaeb", "⚠️"),
    SAFE: ("#05603a", "#ecfdf3", "✅"),
    UNSURE: ("#344054", "#f2f4f7", "❔"),
}
LEVEL_COLOR = {CRITICAL: "#b42318", HIGH: "#c4320a", MEDIUM: "#b54708"}
LINK_STYLE = {"Dangerous": ("#b42318", "#fef3f2", "⛔"), "Suspicious": ("#93370d", "#fffaeb", "⚠️"),
              "Official website": ("#05603a", "#ecfdf3", "✅"), "No warning signs found": ("#344054", "#f2f4f7", "ℹ️")}
INDICATOR_ICON = {"danger": "⛔", "warning": "⚠️", "info": "ℹ️", "good": "✅"}

EXAMPLES = {
    "Bank KYC message": "Dear customer your account will be blocked today. Update your KYC immediately: http://sbi-kyc-update.example.xyz",
    "'Hi Mum' message": "Hi Mum, I dropped my phone, this is my new number. Can you send me money urgently? Don't tell Dad.",
    "Police video call": "This is Mumbai Cyber Crime. A parcel in your name has drugs. Join the video call now, you are under digital arrest. Don't tell your family.",
    "'Wrong number' chat": "Priya: Hi, is this Ananya?\nYou: No, wrong number\nPriya: Oh sorry! You seem nice though. Where are you from?\nYou: Bangalore\nPriya: I work in fashion in Singapore. My uncle is a crypto mentor, he helped me earn 40% profit last week\nPriya: Join our VIP trading group, guaranteed returns. Just deposit Rs 10,000 to start",
    "Real OTP": "482915 is your OTP for login. Do not share it with anyone. Bank staff will never ask for it.",
}

# --- settings ------------------------------------------------------------------------------------
st.title("🪔 Jagratha")
st.caption("జాగ్రత్త · ஜாக்கிரதை · ಜಾಗ್ರತೆ · ജാഗ്രത · जाग्रत · জাগ্রত: *be careful*, the way elders say it. "
           "Check any message, chat or link before you trust it.")
lang_now = st.session_state.get("language", "English")
with st.expander(f"⚙️ Language ({lang_now}), text size and view"):
    language = st.selectbox("Language for the answer and voice", list(i18n.VOICE_CODES), key="language")
    large = st.toggle("Large text", key="large")
    simple = st.toggle("Simple view", key="simple",
                       help="Show just the answer and what to do. The evidence stays one tap away.")
    online_possible = llm.available() or reputation.enabled()
    allow_online = st.toggle("Use online services", key="online", disabled=not online_possible,
                             help=None if online_possible else "Not set up on this app.")
    if online_possible:
        st.caption("Off by default: everything is checked on this server. When on, links can be checked with "
                   "Google Safe Browsing, hard-to-read photos can be read by OpenAI, and you can ask OpenAI for "
                   "an explanation. Phone numbers, accounts, codes and other personal details are masked "
                   "before any text is sent.")
allow_online = bool(st.session_state.get("online")) and (llm.available() or reputation.enabled())

@st.cache_resource(show_spinner="Loading the model…")
def warm_model():
    """Load the classifier once for the whole server, not per user or request."""
    return ml.load()


warm_model()
base = 23 if large else 18
st.markdown(f"""
<style>
  html, body, [class*="css"], .stMarkdown p, .stMarkdown li {{ font-size: {base}px; }}
  .verdict {{ border-radius: 14px; padding: 1.1rem 1.3rem; margin: 1rem 0 0.5rem; }}
  .verdict h2 {{ margin: 0; font-size: {base * 1.75:.0f}px; }}
  .verdict p {{ margin: 0.3rem 0 0; font-size: {base}px; }}
  .verdict .sub {{ font-weight: 600; }}
  .verdict .local {{ font-size: {base * 1.15:.0f}px; font-weight: 600; margin-top: 0.5rem; }}
  .badge {{ display: inline-block; color: #fff; border-radius: 6px; padding: 0.05rem 0.45rem;
            font-size: 0.8em; font-weight: 600; margin-right: 0.4rem; vertical-align: middle; }}
  .sos {{ background: #b42318; color: #fff; border-radius: 12px; padding: 0.9rem 1.1rem; margin: 0.8rem 0; }}
  .sos a {{ color: #fff; font-weight: 700; text-decoration: underline; }}
  .sos .big {{ font-size: {base * 1.3:.0f}px; font-weight: 700; }}
  .calm {{ background: #eff8ff; color: #1849a9; border: 2px solid #1849a9; border-radius: 12px;
           padding: 0.9rem 1.1rem; margin: 0.5rem 0 1rem; }}
  .calm .big {{ font-size: {base * 1.25:.0f}px; font-weight: 700; }}
  .script {{ background: #ffffff; color: #101828; border-left: 6px solid #1d4ed8; border-radius: 8px;
             padding: 0.7rem 1rem; margin: 0.4rem 0; font-size: {base * 1.2:.0f}px; font-weight: 600;
             box-shadow: 0 1px 2px rgba(16,24,40,.08); }}
  .script .sub {{ font-size: {base * 0.85:.0f}px; font-weight: 400; color: #475467; margin-top: 0.2rem; }}
  .msgbox {{ border: 1px solid #d0d5dd; border-radius: 10px; padding: 0.8rem 1rem; line-height: 1.7;
             background: #ffffff; color: #101828; }}
  .bubble {{ max-width: 85%; border-radius: 12px; padding: 0.5rem 0.75rem; margin: 0.25rem 0; color: #101828; }}
  .them {{ background: #f2f4f7; margin-right: auto; }}
  .you {{ background: #d1fadf; margin-left: auto; }}
  .flagged {{ border: 2px solid #d92d20; }}
  .who {{ font-size: 0.75em; color: #475467; font-weight: 600; }}
  .flag {{ font-size: 0.85em; color: #b42318; margin-top: 0.2rem; }}
  .turnpoint {{ text-align: center; color: #b42318; font-weight: 700; margin: 0.6rem 0; }}
  textarea {{ font-size: {base * 1.05:.0f}px !important; }}
</style>
""", unsafe_allow_html=True)


# --- shared pieces ------------------------------------------------------------------------------
def js_string(value: str) -> str:
    """A JavaScript string literal that's safe inside <script>, even if the text
    (which may come from the LLM) contains "</script>" or other markup."""
    return (json.dumps(value).replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def speak_button(text: str, lang: str, key: str) -> None:
    """Reads text aloud with the device's own voices (no data leaves the phone)."""
    code = i18n.VOICE_CODES.get(lang, "en-IN")
    st.iframe(f"""
<div style="font-family:sans-serif">
  <button id="b" style="font-size:18px;padding:10px 18px;border-radius:10px;border:none;
    background:#1d4ed8;color:#fff;cursor:pointer">🔊 Listen</button>
  <button id="s" style="font-size:18px;padding:10px 14px;border-radius:10px;border:1px solid #98a2b3;
    background:#fff;color:#101828;cursor:pointer;margin-left:6px">■ Stop</button>
  <div id="m" style="font-size:14px;color:#667085;margin-top:6px"></div>
</div>
<script>
const text = {js_string(text)}, lang = {js_string(code)};
const m = document.getElementById('m');
function voice() {{
  const vs = speechSynthesis.getVoices();
  return vs.find(v => v.lang === lang) || vs.find(v => v.lang.replace('_','-').startsWith(lang.split('-')[0]));
}}
document.getElementById('b').onclick = () => {{
  if (!('speechSynthesis' in window)) {{ m.textContent = "This browser can't read aloud."; return; }}
  speechSynthesis.cancel();
  const u = new SpeechSynthesisUtterance(text);
  u.lang = lang; u.rate = 0.85;
  const v = voice();
  if (v) u.voice = v;
  else if (lang !== 'en-IN') m.textContent = "This device has no voice for this language installed, so it may not read correctly.";
  speechSynthesis.speak(u);
}};
document.getElementById('s').onclick = () => speechSynthesis.cancel();
</script>""", height=95)


def sos_banner() -> None:
    st.markdown(
        '<div class="sos"><div class="big">Already sent money or shared an OTP?</div>'
        f'Call <a href="tel:{emergency.HELPLINE}">{emergency.HELPLINE}</a> now, then your bank. '
        f'Report at <a href="{emergency.PORTAL}" target="_blank">cybercrime.gov.in</a>. '
        "The first few hours matter most.</div>", unsafe_allow_html=True)


def app_url() -> str | None:
    """This app's own address, for the family message (works locally and on Streamlit Cloud)."""
    try:
        parts = urlsplit(st.context.url)
        return f"{parts.scheme}://{parts.netloc}" if parts.netloc else None
    except Exception:
        return None


def share_buttons(text: str, key: str, label: str = "Ask my family") -> None:
    """Open the user's own WhatsApp or SMS app with the message ready. Nothing goes through the server."""
    st.markdown(f"**👨‍👩‍👧 {label}**")
    a, b = st.columns(2)
    a.link_button("Send on WhatsApp", circle.whatsapp_link(text), width="stretch")
    b.link_button("Send as SMS", circle.sms_link(text), width="stretch")
    with st.expander("See the message first"):
        st.code(text, language=None, wrap_lines=True)
        st.caption("You choose who to send it to in WhatsApp or your messages app. Links are made "
                   "unclickable so nobody opens the scam link by accident, and your OTPs and account "
                   "numbers are hidden.")


def call_mode() -> None:
    st.markdown(f'<div class="calm"><div class="big">{html.escape(i18n.phrase("call_calm", language))}</div>'
                + ("" if language == "English" else f'<div>{html.escape(i18n.phrase("call_calm", "English"))}</div>')
                + "</div>", unsafe_allow_html=True)
    st.markdown("**Say this to the caller:**")
    for key in ("call_say1", "call_say2"):
        line = i18n.phrase(key, language)
        sub = "" if language == "English" else f'<div class="sub">{html.escape(i18n.phrase(key, "English"))}</div>'
        st.markdown(f'<div class="script">“{html.escape(line)}”{sub}</div>', unsafe_allow_html=True)
    st.markdown(f"**Then:** {i18n.phrase('call_hangup', language)}")
    a, b = st.columns(2)
    a.link_button(f"📞 Call {emergency.HELPLINE}", f"tel:{emergency.HELPLINE}", type="primary", width="stretch")
    b.link_button("💬 Alert my family", circle.whatsapp_link(circle.call_alert(language, app_url())),
                  width="stretch")
    st.caption("Calling 1930 is free. Your family gets a WhatsApp message asking them to call you; "
               "you choose who in WhatsApp.")

    st.markdown("**Is the caller doing any of these?** Tick what's true.")
    ticked = [c.key for c in oncall.CHECKS if st.checkbox(c.question, key=f"call_{c.key}")]
    advice = oncall.assess_call(ticked)
    if advice.is_scam:
        st.markdown(f'<div class="sos"><div class="big">{advice.headline}</div>'
                    + "".join(f"<div>• {html.escape(r)}</div>" for r in advice.reasons) + "</div>",
                    unsafe_allow_html=True)
    else:
        st.info(advice.headline)

    speak_button(" ".join(i18n.phrase(k, language) for k in ("call_calm", "call_say1", "call_say2", "call_hangup")),
                 language, key="speak_call")
    st.caption("Tip: if you're using the phone for the call, use speaker mode or headphones to read this screen.")


def complaint_kit(report) -> None:
    st.subheader("📝 Complaint kit")
    st.write("Answer a few questions and get a complaint ready to file on cybercrime.gov.in, plus a request "
             "for your bank. Details from the message you checked are filled in for you. Nothing is stored.")
    pre = complaint.from_report(report)
    with st.form("complaint_form"):
        happened = st.multiselect("What happened?", list(emergency.SITUATIONS), format_func=emergency.SITUATIONS.get)
        c1, c2 = st.columns(2)
        when_date = c1.date_input("Date", value=date.today(), max_value=date.today(), format="DD/MM/YYYY")
        when_time = c2.time_input("Approximate time", value=None)
        contact = st.selectbox("How did they contact you?", complaint.CONTACT_METHODS, index=None)
        claimed = st.text_input("Who did they pretend to be?", value=pre.get("claimed_to_be", ""))
        c3, c4 = st.columns(2)
        amount = c3.number_input("Amount lost (Rs)", min_value=0.0, step=100.0, format="%.2f")
        method = c4.selectbox("Paid by", complaint.PAYMENT_METHODS, index=None)
        utrs = st.text_area("Transaction ID / UTR numbers (one per line)",
                            help="Find these in your bank or UPI app's payment history.", height=80)
        bank = st.text_input("Your bank or payment app", placeholder="e.g. SBI, HDFC Bank, PhonePe")
        phones = st.text_area("Scammer's phone numbers (one per line)", value="\n".join(pre.get("suspect_phones", [])), height=70)
        pay_ids = st.text_area("UPI IDs or accounts they asked you to pay (one per line)",
                               value="\n".join(pre.get("suspect_payment_ids", [])), height=70)
        links = st.text_area("Links or websites (one per line)", value="\n".join(pre.get("suspect_links", [])), height=70)
        story = st.text_area("What happened, in your own words (any language)", height=120,
                             placeholder="e.g. I got a call from someone saying they were from the police…")
        made = st.form_submit_button("Make my complaint", type="primary", width="stretch")
    if made:
        lines = lambda t: [x.strip() for x in t.splitlines() if x.strip()]
        st.session_state.incident = complaint.Incident(
            happened=happened, when_date=when_date, when_time=when_time, contact_method=contact or "",
            claimed_to_be=claimed, scam_type=pre.get("scam_type", ""), amount=amount, payment_method=method or "",
            transaction_ids=lines(utrs), user_bank=bank, suspect_phones=lines(phones),
            suspect_payment_ids=lines(pay_ids), suspect_links=lines(links),
            suspect_other=pre.get("suspect_other", []), description=story)
    inc = st.session_state.get("incident")
    if inc:
        st.success(f"Ready. On cybercrime.gov.in, choose: {complaint.portal_category(inc)}.")
        st.markdown("**1. Complaint summary**: copy it with the button in the corner and paste it into the portal.")
        st.code(complaint.complaint_text(inc), language=None, wrap_lines=True)
        st.markdown("**2. Request to your bank**: send it from the bank's official app, email or branch.")
        st.code(complaint.bank_request(inc), language=None, wrap_lines=True)
        st.markdown("**3. Evidence to keep**")
        for item in complaint.evidence_checklist(inc):
            st.markdown(f"- {item}")
        d1, d2 = st.columns(2)
        d1.download_button("Download (print or save as PDF)", complaint.as_html(inc), file_name="complaint-kit.html",
                           mime="text/html", width="stretch")
        d2.download_button("Download as text", complaint.as_text(inc), file_name="complaint-kit.txt",
                           mime="text/plain", width="stretch")


def emergency_steps(key: str) -> None:
    st.markdown("**What happened?** Tick all that apply.")
    chosen = [k for k, label in emergency.SITUATIONS.items() if st.checkbox(label, key=f"{key}_{k}")]
    for i, step in enumerate(emergency.steps_for(chosen), 1):
        st.markdown(f"{i}. {step}")


def ai_explanation(rep, lang: str) -> llm.Explanation | None:
    """The AI explanation if the user asked for one (for this result and language)."""
    return st.session_state.get("ai", {}).get((id(rep), lang))


def render_timeline(conv: dict) -> None:
    first = conv["first_suspicious_message"]
    parts = []
    for t in conv["timeline"]:
        if first and t["message_number"] == first:
            parts.append(f'<div class="turnpoint">⚠️ It becomes suspicious here (message {first})</div>')
        side = "you" if t["is_user"] or t["from"].lower() in ("you", "me") else "them"
        flagged = " flagged" if t["red_flags"] else ""
        flags = "".join(f'<div class="flag">⚠ {html.escape(f)}</div>' for f in t["red_flags"][:2])
        parts.append(f'<div class="bubble {side}{flagged}"><div class="who">{t["message_number"]}. '
                     f'{html.escape(t["from"])}</div>{html.escape(t["text"]).replace(chr(10), "<br>")}{flags}</div>')
    st.markdown('<div style="display:flex;flex-direction:column">' + "".join(parts) + "</div>", unsafe_allow_html=True)
    if not first:
        st.caption("No message in this chat has a clear red flag.")


def render_result(result, photos: list[dict]) -> None:
    rep = result.report
    for p in photos:
        with st.expander(f"Text found in {p['name']}", expanded=False):
            a, b = st.columns([1, 2])
            a.image(p["data"], width="stretch")
            b.text(p["text"] or "No text found in this image.")
            b.caption(f"Read with {p['method']}. If something is wrong, paste the text in the box instead.")

    if rep.analysis.get("input_truncated"):
        st.info(f"This was very long, so only the most recent {safety.MAX_MESSAGE_CHARS:,} characters were checked.")

    # 1. The answer, in English and the chosen language.
    fg, bg, icon = STYLE[result.verdict]
    local = "" if language == "English" else f'<p class="local">{html.escape(i18n.PHRASES[language][result.verdict])}</p>'
    st.markdown(f'<div class="verdict" style="background:{bg};color:{fg};border:2px solid {fg}">'
                f'<h2>{icon} {result.verdict}</h2><p class="sub">{result.subtitle}</p>'
                f'<p>{html.escape(result.detail)}</p>{local}</div>', unsafe_allow_html=True)

    ai = ai_explanation(rep, language)
    summary = ai or llm.Explanation(llm.template_explanation(rep), "template")
    spoken = summary.text if (summary.source == "llm" or language == "English") else i18n.spoken_summary(result.verdict, language)
    speak_button(spoken, language, key="speak")

    # 2. Emergency help, prominently, whenever there's a warning.
    if result.verdict in (SCAM, CAREFUL) and oncall.suggests_live_call(s.id for s in result.signals):
        st.warning("**Are you on a call with them right now?** Open the **📞 On a call** tab for what to say, "
                   "and hang up.")
    if result.verdict in (SCAM, CAREFUL):
        sos_banner()
        with st.expander("Step-by-step help if you already paid or shared details"):
            emergency_steps("sos_result")
            st.caption("The **🆘 Help** tab can also prepare your complaint for cybercrime.gov.in and your bank.")
    if result.verdict in (SCAM, CAREFUL, UNSURE):
        share_buttons(circle.family_message(result, language, app_url()), key="share_result")

    # 3. Exactly why.
    st.subheader("Exactly what's suspicious")
    if rep.conversation:
        render_timeline(rep.conversation)
    else:
        marks, notes = find_marks(result.text, result.categories)
        if notes:
            st.markdown(f'<div class="msgbox">{highlighted_html(result.text, marks)}</div>', unsafe_allow_html=True)
            for n in notes:
                st.markdown(f'**{n.number}.** {n.reason} <span class="badge" style="background:{LEVEL_COLOR[n.level]}">'
                            f'{n.level}</span>', unsafe_allow_html=True)
        elif result.verdict == CAREFUL:
            st.write("No single sentence stands out, but the overall wording is very similar to scam messages.")
        else:
            st.write("Nothing in the message matches a known scam tactic.")

    st.subheader("In simple words")
    if language != "English" and summary.source != "llm":
        st.markdown(f"**{i18n.spoken_summary(result.verdict, language)}**")
    st.write(summary.text)
    if summary.source == "llm":
        st.caption("Written by AI (OpenAI) from the detection results, with personal details masked. "
                   "It can't change the verdict.")
    elif summary.note:
        st.caption(summary.note)
    if allow_online and llm.available() and summary.source != "llm":
        if st.button(f"✨ Explain in simple {language} with AI", key="ask_ai"):
            with st.spinner("Asking the AI to explain…"):
                st.session_state.setdefault("ai", {})[(id(rep), language)] = llm.explain(rep, language)
            telemetry.emit({"event": "llm_explanation", "language": language})
            st.rerun()
        with st.expander("What would be sent to the AI"):
            st.caption("Only these detection results, with personal details replaced by placeholders. "
                       "Never the full message, and never your photos.")
            st.json(llm.outgoing_evidence(rep)[0], expanded=False)

    lessons = education.lessons_for(result.signals) if result.verdict in (SCAM, CAREFUL) else []
    if lessons:
        with st.expander(f"📚 How this scam works: {lessons[0].title}", expanded=not simple):
            for i, ls in enumerate(lessons):
                if i:
                    st.markdown(f"#### {ls.title}")
                st.markdown(f"**How it works.** {ls.how_it_works}")
                st.markdown(f"**The trick.** {ls.lever}")
                st.markdown(f"**The fact that breaks it.** {ls.the_fact}")
                st.markdown(f"**Your habit from now on.** {ls.habit}")

    st.subheader("What to do")
    for a in rep.recommended_actions:
        st.markdown(f"- {a}")

    st.markdown(f"**Confidence: {rep.confidence}.** " + " ".join(rep.confidence_reasons))
    st.progress(result.risk_score / 100, text=f"Risk score: {result.risk_score} / 100")
    st.caption("How much scam evidence was found, weighted by how dangerous each tactic is. "
               "It is not the chance that this message is a scam.")

    # 4. Full evidence (folded away in simple view).
    with st.expander("See all the evidence", expanded=not simple):
        if rep.scam_types:
            st.markdown("**Looks like:** " + ", ".join(rep.scam_types))
        if rep.impersonated_organisation:
            st.markdown(f"**Pretending to be:** {rep.impersonated_organisation}")
        if rep.conversation and rep.conversation["conversation_findings"]:
            st.markdown("**Across the conversation**")
            for f in rep.conversation["conversation_findings"]:
                st.markdown(f"- {f}")
        present = [c for c in result.categories if c.present and
                   (c.category.key != "scam_wording" or result.verdict in (SCAM, CAREFUL))]
        for c in present:
            st.markdown(f'<span class="badge" style="background:{LEVEL_COLOR[c.category.level]}">{c.category.level}</span>'
                        f'**{c.category.name}**', unsafe_allow_html=True)
            for reason in dict.fromkeys(sig.reason for sig in c.signals):
                st.markdown(f"- {reason}")
        if rep.urls:
            st.markdown("**Links**")
            st.dataframe([{"Website": u.host, "Check": u.assessment.replace("_", " "),
                           "Pretends to be": u.claims_to_be or "", "Blocklist": u.reputation, "Note": u.note}
                          for u in rep.urls], hide_index=True, width="stretch")
            st.caption("Check any link in more detail on the 🔗 Link tab.")
        if rep.phone_numbers or rep.payment_ids or rep.emails:
            st.markdown("**Contact and payment details in the message**")
            for ph in rep.phone_numbers:
                st.markdown(f"- 📞 {ph.number} ({ph.kind}). {ph.note}")
            for pid in rep.payment_ids:
                st.markdown(f"- 💸 {pid} (UPI ID). Never pay a UPI ID you can't verify.")
            for em in rep.emails:
                st.markdown(f"- ✉️ {em}")
        weak = [c for c in result.categories if not c.present]
        if weak:
            st.markdown("**Weaker signs** (not enough on their own)")
            for c in weak:
                for reason in dict.fromkeys(sig.reason for sig in c.signals):
                    st.markdown(f"- {c.category.name}: {reason}")
        if rep.missing_information:
            st.markdown("**What would help us be more sure**")
            for m in rep.missing_information:
                st.markdown(f"- {m}")
        st.download_button("Download the evidence (JSON)", json.dumps(rep.to_dict(), ensure_ascii=False, indent=2),
                           file_name="jagratha-evidence.json", mime="application/json")
        st.json({"language": rep.language.to_dict(), "input_type": rep.source, "analysis": rep.analysis,
                 "ml_model_output_uncalibrated": None if result.model_score is None else round(result.model_score, 3),
                 "words_that_raised_the_model_output": result.suspicious_words}, expanded=False)

    with st.expander("Was this right? Tell us"):
        kind = st.radio("Your report", list(feedback.KINDS), format_func=feedback.KINDS.get,
                        index=None, key="fb_kind", label_visibility="collapsed")
        share = st.checkbox("Also share this message so a person can review it (phone numbers, accounts, "
                            "codes and other personal details are masked first)", key="fb_share")
        comment = st.text_input("Anything else? (optional)", key="fb_comment", max_chars=500)
        if st.button("Send report", key="fb_send", disabled=kind is None):
            count = st.session_state.get("fb_count", 0)
            msg = feedback.submit(feedback.build_record(kind, result, share, comment), count)
            st.session_state.fb_count = count + 1
            st.success(msg)
        st.caption("Reports are reviewed by a person before they're used to improve the checker. "
                   "Without the box ticked, only the type of report and the verdict are stored.")


# Photos are read once and kept only in this visitor's session (never cached
# across users or written to disk).


tab_msg, tab_link, tab_call, tab_help = st.tabs(["📩 Message", "🔗 Link", "📞 On a call", "🆘 Help"])

# --- tab 1: messages and conversations --------------------------------------------------------------
with tab_msg:
    st.write("Paste a message or a whole chat, or tap + to add a screenshot.")
    if "text" not in st.session_state:
        st.session_state.text = ""
    if "show_upload" not in st.session_state:
        st.session_state.show_upload = False

    def use_example():
        choice = st.session_state.get("example")
        if choice:
            st.session_state.text = EXAMPLES[choice]
            st.session_state.pop("result", None)
            st.session_state.example = None

    box, plus = st.columns([0.9, 0.1], vertical_alignment="top")
    with box:
        text = st.text_area("Message", key="text", height=150, max_chars=safety.MAX_MESSAGE_CHARS * 2,
                            placeholder="Paste an SMS, WhatsApp, email, a whole chat (copied or exported), "
                                        "or describe a call you got…",
                            label_visibility="collapsed")
    with plus:
        if st.button("", key="plus", icon=":material/close:" if st.session_state.show_upload else ":material/add:",
                     help="Close" if st.session_state.show_upload else "Add a screenshot or photo",
                     width="stretch"):
            st.session_state.show_upload = not st.session_state.show_upload
            st.rerun()

    photos = []
    if st.session_state.show_upload:
        photos = st.file_uploader("Add a screenshot or photo of the message or chat. You can add more than one, "
                                  "for example a long chat in parts.",
                                  type=["png", "jpg", "jpeg", "webp"], accept_multiple_files=True, key="photos")
    if photos:
        st.caption(f"{len(photos)} photo{'s' if len(photos) > 1 else ''} added. Press Check message to read "
                   f"{'them' if len(photos) > 1 else 'it'}.")
    st.pills("Or try an example", list(EXAMPLES), key="example", on_change=use_example)
    if ml.load() is None:
        st.info("The ML model isn't trained yet, so only the red-flag rules are used. Run `python -m scripts.train`.")

    if st.button("Check message", type="primary", width="stretch"):
        st.session_state.pop("result", None)
        if not text.strip() and not photos:
            st.warning("Paste a message or add a photo with +, then press Check message.")
        else:
            read = []
            if len(photos) > safety.MAX_IMAGES:
                st.warning(f"Only the first {safety.MAX_IMAGES} photos are read.")
                photos = photos[:safety.MAX_IMAGES]
            if photos and not ocr.available(allow_online):
                st.error("Reading photos isn't set up here yet. Install Tesseract OCR (see the README) "
                         "or paste the message text instead.")
            elif photos:
                with st.spinner("Reading the text in your photo…"):
                    for p in photos:
                        try:
                            o = ocr.read_image(p.getvalue(), allow_online)
                            read.append({"name": p.name, "data": p.getvalue(), "text": o.text,
                                         "method": o.method + (f". {o.note}" if o.note else "")})
                        except safety.UnsafeInput as e:
                            st.error(f"{p.name}: {e}")
                        except Exception as e:
                            st.error(f"Couldn't read {p.name} ({type(e).__name__}). Try a clearer screenshot "
                                     "or paste the text.")
            combined = "\n".join(t for t in [text.strip(), *(p["text"] for p in read)] if t.strip())
            if combined:
                source = "photo" if read and not text.strip() else "text"
                result = check(combined, source=source, allow_online=allow_online)
                st.session_state.result = (result, read)
                st.session_state.pop("ai", None)
                telemetry.emit(telemetry.check_event(result, len(combined)))
            elif photos:
                st.warning("No text could be found in the photo. Try a clearer screenshot or paste the message.")

    if "result" in st.session_state:
        render_result(*st.session_state.result)

# --- tab 2: links -----------------------------------------------------------------------------------
with tab_link:
    st.write("Got a link and not sure about it? Paste just the link here. It is **not opened** unless you ask.")
    url = st.text_input("Link", placeholder="e.g. bit.ly/abc123 or sbi-rewards-claim.in/login",
                        label_visibility="collapsed", key="url")
    if st.button("Check link", type="primary", width="stretch"):
        st.session_state.pop("redirects", None)
        try:
            st.session_state.link = inspect_link(url, online=allow_online) if url.strip() else None
            if not url.strip():
                st.warning("Paste a link first.")
        except ValueError as e:
            st.session_state.link = None
            st.warning(str(e))

    lr = st.session_state.get("link")
    if lr:
        fg, bg, icon = LINK_STYLE[lr.verdict]
        st.markdown(f'<div class="verdict" style="background:{bg};color:{fg};border:2px solid {fg}">'
                    f'<h2>{icon} {lr.verdict}</h2><p>{html.escape(lr.info.host)}</p></div>', unsafe_allow_html=True)
        for ind in lr.indicators:
            st.markdown(f"{INDICATOR_ICON[ind.level]} {ind.text}")
        st.dataframe([{"Website name": lr.info.host, "Registered domain": lr.info.domain,
                       "Pretends to be": lr.info.claims_to_be or "", "Blocklist check": lr.info.reputation}],
                     hide_index=True, width="stretch")
        if lr.verdict == "No warning signs found":
            st.info("No warning signs isn't the same as safe: new scam sites look ordinary. Only enter passwords "
                    "or pay on websites you went to yourself, not ones sent to you.")
        if lr.verdict in ("Dangerous", "Suspicious"):
            st.markdown("**Don't open this link.** If you already did, don't enter any details there.")

        st.markdown("**Where does it really lead?**")
        st.caption("This contacts the website from our server (not your phone) and follows its redirects, "
                   "without loading the page. Some scam links are unique to each person, so the scammer "
                   "may be able to tell the link was checked.")
        if st.button("Follow the redirects", key="follow"):
            with st.spinner("Following the link…"):
                chain = redirects.follow(lr.url)
            st.session_state.redirects = chain
        chain = st.session_state.get("redirects")
        if chain:
            for i, hop in enumerate(chain, 1):
                status = hop.get("stopped") or f"HTTP {hop['status']}"
                st.markdown(f"{i}. `{hop['url']}` ({status})")
            final = chain[-1]["url"]
            if len(chain) > 1:
                try:
                    end = inspect_link(final)
                    st.markdown(f"**Final destination: {end.info.host} ({end.verdict.lower()}).**")
                    for ind in end.indicators:
                        if ind.level in ("danger", "warning", "good"):
                            st.markdown(f"{INDICATOR_ICON[ind.level]} {ind.text}")
                except ValueError:
                    pass
    if not reputation.enabled():
        st.caption("Blocklist checks are off on this app. They need a free Google Safe Browsing key (see the README).")

# --- tab 3: emergency -------------------------------------------------------------------------------
with tab_call:
    call_mode()

with tab_help:
    sos_banner()
    st.write("Tell us what happened and we'll show what to do, most urgent first.")
    emergency_steps("sos_tab")
    speak_button(i18n.PHRASES[language]["paid"], language, key="speak_sos")
    st.divider()
    last = st.session_state.get("result")
    complaint_kit(last[0].report if last else None)

st.divider()
with st.expander("🔒 How your messages and photos are handled"):
    st.markdown(f"""
- **Nothing is stored.** Messages and photos are checked in memory and forgotten when you close the page.
  They aren't saved to disk, a database or logs.
- **Checked on this server by default.** Rules, the ML model, link analysis and photo reading all run here.
- **Online services only if you turn them on** (in ⚙️ settings{"" if online_possible else "; not set up on this app"}).
  Then: links may be checked with Google Safe Browsing; a photo is sent to OpenAI only if it couldn't be read here;
  and an AI explanation is generated only when you press the button, from the detection results with phone numbers,
  accounts, codes and other personal details masked.
- **Nothing is opened or run.** Links aren't visited unless you press "Follow the redirects", attachments and apps are
  never downloaded or installed, and photos are checked to be real images before they're read.
- **Logs contain no message content:** only the verdict, which rules fired, timings and similar anonymous details.
- **Feedback** stores message text only if you tick the box, with personal details masked, for human review.
""")
st.caption("Jagratha gives a second opinion, not a guarantee. When in doubt, don't click, don't pay, "
           "and check with someone you trust. In India, report fraud at cybercrime.gov.in or call 1930.")
