"""Scam Shield web app. Run with:  streamlit run app.py"""
import streamlit as st
from dotenv import load_dotenv

from scamshield import analyze
from scamshield import explain as llm
from scamshield import model as ml
from scamshield.analyzer import CAREFUL, SAFE, SCAM

load_dotenv()
st.set_page_config(page_title="Scam Shield", page_icon="🛡️", layout="centered")

STYLE = {
    SCAM: ("#b42318", "#fef3f2", "🚫"),
    CAREFUL: ("#93370d", "#fffaeb", "⚠️"),
    SAFE: ("#05603a", "#ecfdf3", "✅"),
}

EXAMPLES = {
    "Bank KYC message": "Dear customer your account will be blocked today. Update your KYC immediately: http://sbi-kyc-update.example.xyz",
    "'Hi Mum' message": "Hi Mum, I dropped my phone, this is my new number. Can you send me money urgently? Don't tell Dad.",
    "Job offer": "Part time job! Earn Rs 5000 daily by liking YouTube videos. WhatsApp HR now.",
    "Real OTP": "482915 is your OTP for login. Do not share it with anyone. Bank staff will never ask for it.",
}

st.markdown("""
<style>
  html, body, [class*="css"] { font-size: 19px; }
  .verdict { border-radius: 14px; padding: 1.1rem 1.3rem; margin: 1rem 0 0.5rem; }
  .verdict h2 { margin: 0; font-size: 2rem; }
  .verdict p { margin: 0.3rem 0 0; font-size: 1.05rem; }
  textarea { font-size: 1.1rem !important; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Scam Shield")
st.write("Got a message that feels wrong? Paste it below and find out if it's a scam.")

if "text" not in st.session_state:
    st.session_state.text = ""

st.caption("Or try an example:")
cols = st.columns(len(EXAMPLES))
for col, (label, msg) in zip(cols, EXAMPLES.items()):
    if col.button(label, use_container_width=True):
        st.session_state.text = msg

text = st.text_area("Message", key="text", height=150,
                    placeholder="Paste an SMS, WhatsApp, email or describe a call you got…",
                    label_visibility="collapsed")

language = st.selectbox("Explain in", llm.LANGUAGES, disabled=not llm.available(),
                        help=None if llm.available() else "Add an OpenAI API key to get explanations in other languages.")

if ml.load() is None:
    st.info("The ML model isn't trained yet, so only the red-flag rules are used. Run `python -m scripts.train` for full accuracy.")

if st.button("Check message", type="primary", use_container_width=True):
    if not text.strip():
        st.warning("Paste a message first, then press Check message.")
        st.stop()

    result = analyze(text)
    fg, bg, icon = STYLE[result.verdict]
    st.markdown(
        f'<div class="verdict" style="background:{bg};color:{fg};border:2px solid {fg}">'
        f'<h2>{icon} {result.verdict}</h2>'
        f'<p>Scam risk: {round(result.score * 100)}%</p></div>',
        unsafe_allow_html=True,
    )

    if llm.available():
        with st.spinner("Writing a simple explanation…"):
            try:
                st.write(llm.explain(text, result, language))
            except Exception as e:  # network/API problems shouldn't break the app
                st.caption(f"Explanation unavailable right now ({type(e).__name__}).")

    if result.signals:
        st.subheader("Why")
        for s in result.signals:
            st.markdown(f"- {s.reason}")
    elif result.verdict != SAFE:
        st.subheader("Why")
        st.markdown("- It reads like many scam messages the model has learned from.")

    st.subheader("What to do")
    for a in result.advice:
        st.markdown(f"- {a}")

    with st.expander("Technical details"):
        st.write({
            "model_score": None if result.model_score is None else round(result.model_score, 3),
            "rule_score": round(result.rule_score, 3),
            "combined_score": round(result.score, 3),
            "red_flags": [s.id for s in result.signals],
            "words_that_raised_the_score": result.suspicious_words,
        })

st.divider()
st.caption("Scam Shield gives a second opinion, not a guarantee. When in doubt, don't click, don't pay, "
           "and check with someone you trust. In India, report fraud at cybercrime.gov.in or call 1930.")
