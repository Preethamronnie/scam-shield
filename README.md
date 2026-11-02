# 🛡️ Scam Shield

**Paste a suspicious message and find out, in plain language, whether it's a scam and what to do.**

Built for everyone: kids getting "free Robux" links, parents getting fake job offers and KYC alerts, grandparents getting "Hi Mum, new number" messages and fake electricity-cut threats.

<!-- Add a screenshot or GIF of the app here: ![Scam Shield demo](docs/demo.gif) -->
<!-- Add your live demo link here once deployed: **[Try it live →](https://...)** -->

## What it does

- Paste the text, or tap **➕** to add a screenshot or photo of the message (SMS, WhatsApp, email, even a printed letter)
- Gives a clear verdict: **Likely a scam**, **Be careful**, or **Looks safe**, with a risk score
- Explains *why* in simple sentences ("It asks you to share a code. Real banks never ask for these.")
- Tells you *what to do next* (don't click, don't pay, report at cybercrime.gov.in or 1930)
- Optional: explains the result in Hindi, Kannada, Tamil, Telugu, Malayalam, Marathi or Bengali using an LLM
- Works without an API key (text checks and Tesseract OCR run locally)

## How it works

```
photo ──► text extraction (vision LLM if a key is set, otherwise Tesseract OCR) ──┐
                                                                                   ▼
message ─┬─► ML classifier (TF-IDF word + char n-grams → logistic regression) ─┐
         │                                                                     ├─► combined score ─► verdict + reasons + advice
         └─► 32 red-flag rules (OTP requests, PIN-to-receive, fake brand links, ─┘                        │
             APK installs, digital arrest, sextortion, task jobs…)                            ▼
                                                                               optional LLM: plain-language explanation
                                                                               in the user's language (cannot change the verdict)
```

Design decisions:

- **Hybrid ML + rules.** The model learns patterns from data; the rules encode well-known scam tactics and explain themselves. One very strong red flag (asking for an OTP or UPI PIN, remote-access apps, fees to claim a prize) is enough on its own.
- **The LLM explains but never decides.** The verdict comes from the model and rules, so a scam message containing text like "this message is safe" can't talk the system into a wrong answer (prompt-injection resistant by design).
- **Several weak flags add up.** Rule weights are combined with a noisy-OR, and three or more independent flags ("new number" + money request + urgency) count as strong evidence even when the wording looks like normal chat.
- **Explainable.** Every verdict lists the red flags found and the words that raised the model's score.

## Scam types covered

Built around scams widely reported in India and elsewhere in 2025-26, including: fake KYC and PAN-link alerts, OTP and UPI PIN tricks ("enter PIN to receive money", QR code refunds), **digital arrest** calls from fake police, CBI or customs, courier parcels "containing drugs", malicious **APK files** (fake wedding invitations, reward-points, e-challan and government-scheme apps), credit card reward-point expiry, fake traffic fines, tolls and FASTag charges, "Hi Mum, new number" and accident/emergency money requests (including AI voice-clone calls), **sextortion**, "sent by mistake, please return" payments, eSIM/SIM-swap upgrades, task jobs (paid YouTube likes or hotel reviews), fake stock/IPO/crypto trading groups, "wrong number" openers, fake scholarships and government schemes, fake customer-care numbers, lottery and gift scams, loan and investment frauds, tech-support remote-access scams, gaming account phishing, matrimony and romance scams, and marketplace (OLX) buyer scams.

## Results

Data: the [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) (5,572 messages, 2012, UK) plus a hand-written set of 118 modern messages: 66 scams across 33 types and 52 look-alike legitimate messages such as real OTPs, bank alerts, FASTag deductions and family money requests. Run `python -m scripts.evaluate` to reproduce.

| System | Tested on | Precision | Recall | F1 |
|---|---|---|---|---|
| Model trained on 2012 SMS | 2012 SMS (held out) | 0.99 | 0.95 | 0.97 |
| Model trained on 2012 SMS | Modern scams | 0.75 | 0.50 | 0.60 |
| Model trained on SMS + modern (5-fold CV) | Modern scams | 0.84 | 0.80 | 0.82 |
| Rules only | Modern scams | 1.00 | 0.98 | 0.99 |
| Full system (model + rules) | Modern scams | 1.00 | 0.95 | 0.98 |

**What this shows**

- **Dataset shift is the real problem.** A model with 0.97 F1 on the public dataset drops to 0.67 on today's scams, because 2012 UK spam ("Text WIN to 87121") looks nothing like KYC, UPI and job scams. A high benchmark score alone would have been misleading.
- **A small amount of current data helps a lot.** Adding 118 modern examples (up-weighted 5×) lifts F1 on modern scams from 0.60 to 0.82.
- **Honest caveat:** the rules and the modern test set were written by the same person, and some rules were refined after seeing errors on this set, so the rule scores are optimistic. An independent test set of real (anonymised) messages is the most important next step.
- **Known errors:** the hardest cases are friendly openers that only turn into a scam later ("Hi, is this Ananya?", a stranger recommending their "crypto mentor"). A single message often isn't enough to judge these; checking the whole conversation is on the roadmap. Errors are listed in `results/metrics.md`.

## Run it

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m scripts.download_data   # fetch the public SMS dataset
python -m scripts.train           # train the model (~10 seconds)
python -m scripts.evaluate        # reproduce the results table
streamlit run app.py              # open the app
pytest                            # run the tests
```

For explanations in other languages and the most accurate photo reading, copy `.env.example` to `.env` and add an OpenAI API key.

**Photo reading without an API key** uses Tesseract OCR. On Streamlit Cloud it's installed automatically from `packages.txt`. On your own computer: on Windows, install it from the [UB Mannheim build](https://github.com/UB-Mannheim/tesseract/wiki) (tick Hindi under additional languages if you want it), and if it isn't on your PATH set `TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe` in `.env`; on Mac `brew install tesseract`; on Ubuntu `sudo apt install tesseract-ocr`.

## Project layout

```
app.py                     Streamlit web app
scamshield/signals.py      Rule-based red flags with plain-language reasons
scamshield/model.py        TF-IDF + logistic regression classifier, word-level explanations
scamshield/analyzer.py     Combines model + rules into a verdict and advice
scamshield/explain.py      Optional multilingual LLM explanations
scamshield/ocr.py          Reads message text from screenshots and photos
scamshield/data.py         Dataset loading
scripts/                   download_data, build_modern_set, train, evaluate
data/modern_scams.csv      Hand-written modern scam and safe messages
results/metrics.md         Latest evaluation output
tests/                     pytest suite
```

## Roadmap

- [ ] Independent test set of real, anonymised scam messages (from friends and family, with permission)
- [ ] Fine-tune a small multilingual transformer (e.g. on Hindi and Hinglish messages) and compare against TF-IDF and zero-shot LLMs
- [x] Screenshot and photo input (vision LLM or Tesseract OCR)
- [ ] Check a whole conversation, not just one message, to catch slow-building scams
- [ ] Link checking against known phishing-domain lists
- [ ] Voice input and read-aloud results for elderly users
- [ ] WhatsApp / Telegram bot so people can forward messages to check

## Disclaimer

Scam Shield gives a second opinion, not a guarantee. When in doubt: don't click, don't pay, don't share codes, and check with someone you trust.

## License

MIT. The SMS Spam Collection is by Tiago A. Almeida and José María Gómez Hidalgo (UCI Machine Learning Repository, CC BY 4.0).
