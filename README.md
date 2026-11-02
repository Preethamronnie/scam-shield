# 🛡️ Scam Shield

**Paste a suspicious message and find out, in plain language, whether it's a scam and what to do.**

Built for everyone: kids getting "free Robux" links, parents getting fake job offers and KYC alerts, grandparents getting "Hi Mum, new number" messages and fake electricity-cut threats.

<!-- Add a screenshot or GIF of the app here: ![Scam Shield demo](docs/demo.gif) -->
<!-- Add your live demo link here once deployed: **[Try it live →](https://...)** -->

## What it does

- Gives a clear verdict: **Likely a scam**, **Be careful**, or **Looks safe**, with a risk score
- Explains *why* in simple sentences ("It asks you to share a code. Real banks never ask for these.")
- Tells you *what to do next* (don't click, don't pay, report at cybercrime.gov.in or 1930)
- Optional: explains the result in Hindi, Kannada, Tamil, Telugu, Malayalam, Marathi or Bengali using an LLM
- Works fully offline without an API key

## How it works

```
message ─┬─► ML classifier (TF-IDF word + char n-grams → logistic regression) ─┐
         │                                                                     ├─► combined score ─► verdict + reasons + advice
         └─► 19 red-flag rules (OTP requests, PIN-to-receive, fake brand links, ─┘                        │
             fees for prizes, "new number" family scams, remote-access apps…)                            ▼
                                                                               optional LLM: plain-language explanation
                                                                               in the user's language (cannot change the verdict)
```

Design decisions:

- **Hybrid ML + rules.** The model learns patterns from data; the rules encode well-known scam tactics and explain themselves. One very strong red flag (asking for an OTP or UPI PIN, remote-access apps, fees to claim a prize) is enough on its own.
- **The LLM explains but never decides.** The verdict comes from the model and rules, so a scam message containing text like "this message is safe" can't talk the system into a wrong answer (prompt-injection resistant by design).
- **Explainable.** Every verdict lists the red flags found and the words that raised the model's score.

## Results

Data: the [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) (5,572 messages, 2012, UK) plus a hand-written set of 64 modern messages (36 scams across 17 types like KYC, delivery, job, UPI, family, tech-support and gaming scams, and 28 look-alike legitimate messages such as real OTPs and bank alerts). Run `python -m scripts.evaluate` to reproduce.

| System | Tested on | Precision | Recall | F1 |
|---|---|---|---|---|
| Model trained on 2012 SMS | 2012 SMS (held out) | 0.99 | 0.95 | 0.97 |
| Model trained on 2012 SMS | Modern scams | 0.78 | 0.58 | 0.67 |
| Model trained on SMS + modern (5-fold CV) | Modern scams | 0.74 | 0.78 | 0.76 |
| Rules only | Modern scams | 1.00 | 1.00 | 1.00 |
| Full system (model + rules) | Modern scams | 0.94 | 0.92 | 0.93 |

**What this shows**

- **Dataset shift is the real problem.** A model with 0.97 F1 on the public dataset drops to 0.67 on today's scams, because 2012 UK spam ("Text WIN to 87121") looks nothing like KYC, UPI and job scams. A high benchmark score alone would have been misleading.
- **A small amount of current data helps a lot.** Adding 64 modern examples (up-weighted 5×) lifts recall on modern scams from 0.58 to 0.78.
- **Honest caveat:** the rules and the modern test set were written by the same person, so the rules' perfect score is optimistic. An independent test set of real (anonymised) messages is the most important next step.
- **Known errors:** the full system still misses some family-emergency and rental scams (the model scores them as normal chat and pulls the score down) and raises false alarms on some genuine OTP and delivery messages. These are listed in `results/metrics.md`.

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

For explanations in other languages, copy `.env.example` to `.env` and add an OpenAI API key.

## Project layout

```
app.py                     Streamlit web app
scamshield/signals.py      Rule-based red flags with plain-language reasons
scamshield/model.py        TF-IDF + logistic regression classifier, word-level explanations
scamshield/analyzer.py     Combines model + rules into a verdict and advice
scamshield/explain.py      Optional multilingual LLM explanations
scamshield/data.py         Dataset loading
scripts/                   download_data, build_modern_set, train, evaluate
data/modern_scams.csv      Hand-written modern scam and safe messages
results/metrics.md         Latest evaluation output
tests/                     pytest suite
```

## Roadmap

- [ ] Independent test set of real, anonymised scam messages (from friends and family, with permission)
- [ ] Fine-tune a small multilingual transformer (e.g. on Hindi and Hinglish messages) and compare against TF-IDF and zero-shot LLMs
- [ ] Screenshot input: read messages from a photo using OCR or a vision model
- [ ] Link checking against known phishing-domain lists
- [ ] Voice input and read-aloud results for elderly users
- [ ] WhatsApp / Telegram bot so people can forward messages to check

## Disclaimer

Scam Shield gives a second opinion, not a guarantee. When in doubt: don't click, don't pay, don't share codes, and check with someone you trust.

## License

MIT. The SMS Spam Collection is by Tiago A. Almeida and José María Gómez Hidalgo (UCI Machine Learning Repository, CC BY 4.0).
