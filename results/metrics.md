# Jagratha evaluation

## A. ML model on its own (threshold 0.5)

| Model | Tested on | Precision | Recall | FPR | FNR | F1 | TP/FP/FN/TN | PR-AUC | Brier | ECE |
|---|---|---|---|---|---|---|---|---|---|---|
| Trained on 2012 SMS | 2012 SMS (held out) | 0.99 (0.96-1.00) | 0.95 (0.90-0.97) | 0.00 (0.00-0.01) | 0.05 (0.03-0.10) | 0.97 | 141/1/8/965 | 0.986 | 0.008 | 0.019 |
| Trained on 2012 SMS | Modern messages | 0.65 (0.52-0.76) | 0.53 (0.42-0.64) | 0.32 (0.22-0.44) | 0.47 (0.36-0.58) | 0.59 | 39/21/34/45 | 0.668 | 0.272 | 0.169 |
| Trained on SMS + modern (5-fold CV) | Modern messages | 0.77 (0.66-0.85) | 0.81 (0.70-0.88) | 0.27 (0.18-0.39) | 0.19 (0.12-0.30) | 0.79 | 59/18/14/48 | 0.899 | 0.150 | 0.100 |

Calibration: Brier score and expected calibration error (ECE), lower is better. Reliability on modern messages (5-fold CV): if the model were calibrated, the last two columns would match.

| Predicted probability | Messages | Mean predicted | Observed scam rate |
|---|---|---|---|
| 0.0-0.2 | 39 | 0.07 | 0.10 |
| 0.2-0.4 | 14 | 0.30 | 0.50 |
| 0.4-0.6 | 19 | 0.51 | 0.42 |
| 0.6-0.8 | 18 | 0.71 | 0.61 |
| 0.8-1.0 | 49 | 0.93 | 0.88 |

The model's output is used only as corroborating evidence and is never shown to users as a probability; the risk score shown in the app is not calibrated either.

## B. Full system on modern messages

**Verdicts**

| System | True label | Likely a scam | Be careful | Insufficient information | No obvious threat detected |
|---|---|---|---|---|---|
| Rules only | Scam (73) | 57 | 14 | 2 | 0 |
| Rules only | Legitimate (66) | 0 | 0 | 1 | 65 |
| Full system | Scam (73) | 63 | 8 | 2 | 0 |
| Full system | Legitimate (66) | 0 | 0 | 1 | 65 |

**Metrics** (95% confidence intervals in brackets). Two operating points: *strict* counts only "Likely a scam" as flagged, *cautious* also counts "Be careful". "Insufficient information" counts as not flagged, so an undecided scam is a false negative.

| System | Flagged when | Precision | Recall | FPR | FNR | F1 | TP/FP/FN/TN | PR-AUC |
|---|---|---|---|---|---|---|---|---|
| Rules only | strict | 1.00 (0.94-1.00) | 0.78 (0.67-0.86) | 0.00 (0.00-0.06) | 0.22 (0.14-0.33) | 0.88 | 57/0/16/66 | 0.987 |
| Rules only | cautious | 1.00 (0.95-1.00) | 0.97 (0.91-0.99) | 0.00 (0.00-0.06) | 0.03 (0.01-0.09) | 0.99 | 71/0/2/66 | 0.987 |
| Full system | strict | 1.00 (0.94-1.00) | 0.86 (0.77-0.92) | 0.00 (0.00-0.06) | 0.14 (0.08-0.23) | 0.93 | 63/0/10/66 | 0.987 |
| Full system | cautious | 1.00 (0.95-1.00) | 0.97 (0.91-0.99) | 0.00 (0.00-0.06) | 0.03 (0.01-0.09) | 0.99 | 71/0/2/66 | 0.987 |

PR-AUC uses the risk score as a ranking. A random ranking would score 0.525 (the share of scams in this set).

**The two errors that matter most** (full system)

- Dangerous misses, scams labelled "No obvious threat detected": 0 of 73 scams, rate 0.00 (0.00-0.05)
- Scams left as "Insufficient information": 2
- Trust-damaging false alarms, genuine OTP / bank / payment / official-link messages labelled "Likely a scam": 0 of 34, rate 0.00 (0.00-0.10)
- The same messages labelled "Be careful": 0 of 34

Errors and undecided scams (full system):

- MISSED (Insufficient information, risk 0): Hi, is this Ananya? We were supposed to meet for coffee today.
- MISSED (Insufficient information, risk 0): Sorry, wrong number! But you seem nice, where are you from? I'm a fashion designer living in Singapore.

**Risk score thresholds** (full system): what would happen if a single cut-off were used instead of the verdict rules.

| Flag when risk score >= | Precision | Recall | FPR | FNR | F1 | TP/FP/FN/TN |
|---|---|---|---|---|---|---|
| 10 | 1.00 (0.95-1.00) | 0.97 (0.91-0.99) | 0.00 (0.00-0.06) | 0.03 (0.01-0.09) | 0.99 | 71/0/2/66 |
| 20 | 1.00 (0.95-1.00) | 0.96 (0.89-0.99) | 0.00 (0.00-0.06) | 0.04 (0.01-0.11) | 0.98 | 70/0/3/66 |
| 30 | 1.00 (0.94-1.00) | 0.90 (0.82-0.95) | 0.00 (0.00-0.06) | 0.10 (0.05-0.18) | 0.95 | 66/0/7/66 |
| 40 | 1.00 (0.93-1.00) | 0.74 (0.63-0.83) | 0.00 (0.00-0.06) | 0.26 (0.17-0.37) | 0.85 | 54/0/19/66 |
| 50 | 1.00 (0.91-1.00) | 0.53 (0.42-0.64) | 0.00 (0.00-0.06) | 0.47 (0.36-0.58) | 0.70 | 39/0/34/66 |
| 60 | 1.00 (0.89-1.00) | 0.41 (0.31-0.53) | 0.00 (0.00-0.06) | 0.59 (0.47-0.69) | 0.58 | 30/0/43/66 |
| 70 | 1.00 (0.80-1.00) | 0.21 (0.13-0.31) | 0.00 (0.00-0.06) | 0.79 (0.69-0.87) | 0.34 | 15/0/58/66 |

## C. Full system on 2012 SMS held-out messages

1115 real messages (149 spam, 966 legitimate). The spam is mostly 2012 UK marketing and premium-rate spam rather than modern scams, so recall here mainly shows what the system *doesn't* try to catch. The false positive rate on the legitimate messages is the useful number: it's measured on real messages nobody wrote for this project.

**Verdicts**

| System | True label | Likely a scam | Be careful | Insufficient information | No obvious threat detected |
|---|---|---|---|---|---|
| Rules only | Scam (149) | 0 | 28 | 1 | 120 |
| Rules only | Legitimate (966) | 1 | 1 | 42 | 922 |
| Full system | Scam (149) | 26 | 98 | 1 | 24 |
| Full system | Legitimate (966) | 1 | 1 | 42 | 922 |

**Metrics** (95% confidence intervals in brackets). Two operating points: *strict* counts only "Likely a scam" as flagged, *cautious* also counts "Be careful". "Insufficient information" counts as not flagged, so an undecided scam is a false negative.

| System | Flagged when | Precision | Recall | FPR | FNR | F1 | TP/FP/FN/TN | PR-AUC |
|---|---|---|---|---|---|---|---|---|
| Rules only | strict | 0.00 (0.00-0.79) | 0.00 (0.00-0.03) | 0.00 (0.00-0.01) | 1.00 (0.97-1.00) | 0.00 | 0/1/149/965 | 0.278 |
| Rules only | cautious | 0.93 (0.79-0.98) | 0.19 (0.13-0.26) | 0.00 (0.00-0.01) | 0.81 (0.74-0.87) | 0.31 | 28/2/121/964 | 0.278 |
| Full system | strict | 0.96 (0.82-0.99) | 0.17 (0.12-0.24) | 0.00 (0.00-0.01) | 0.83 (0.76-0.88) | 0.30 | 26/1/123/965 | 0.872 |
| Full system | cautious | 0.98 (0.94-1.00) | 0.83 (0.76-0.88) | 0.00 (0.00-0.01) | 0.17 (0.12-0.24) | 0.90 | 124/2/25/964 | 0.872 |

PR-AUC uses the risk score as a ranking. A random ranking would score 0.134 (the share of scams in this set).

**The two errors that matter most** (full system)

- Dangerous misses, scams labelled "No obvious threat detected": 24 of 149 scams, rate 0.16 (0.11-0.23)
- Scams left as "Insufficient information": 1
- Legitimate messages labelled "Likely a scam": 1 of 966, rate 0.00 (0.00-0.01)

Errors and undecided scams (full system):

- FALSE ALARM (Be careful, risk 38): Great. So should i send you my account number.
- MISSED (No obvious threat detected, risk 0): FreeMsg Hey there darling it's been 3 week's now and no word back! I'd like some fun you up for it still? Tb ok! XxX std chgs to send, £1.50 to rcv
- MISSED (No obvious threat detected, risk 0): Dear Voucher Holder 2 claim your 1st class airport lounge passes when using Your holiday voucher call 08704439680. When booking quote 1st class x 2
- MISSED (Insufficient information, risk 0): ringtoneking 84484
- MISSED (No obvious threat detected, risk 0): Sorry I missed your call let's talk when you have the time. I'm on 07090201529
- MISSED (No obvious threat detected, risk 0): Latest News! Police station toilet stolen, cops have nothing to go on!
- MISSED (No obvious threat detected, risk 9): Sunshine Quiz! Win a super Sony DVD recorder if you canname the capital of Australia? Text MQUIZ to 82277. B
- MISSED (No obvious threat detected, risk 7): TheMob>Hit the link to get a premium Pink Panther game, the new no. 1 from Sugababes, a crazy Zebra animation or a badass Hoody wallpaper-all 4 FREE!
- MISSED (No obvious threat detected, risk 0): Bought one ringtone and now getting texts costing 3 pound offering more tones etc
- MISSED (No obvious threat detected, risk 0): Romantic Paris. 2 nights, 2 flights from £79 Book now 4 next year. Call 08704439680Ts&Cs apply.
- MISSED (No obvious threat detected, risk 0): Can U get 2 phone NOW? I wanna chat 2 set up meet Call me NOW on 09096102316 U can cum here 2moro Luv JANE xx Calls£1/minmoremobsEMSPOBox45PO139WA
- FALSE ALARM (Likely a scam, risk 51): Send me your id and password
- MISSED (No obvious threat detected, risk 0): More people are dogging in your area now. Call 09090204448 and join like minded guys. Why not arrange 1 yourself. There's 1 this evening. A£1.50 minAPN LS278BB
- MISSED (No obvious threat detected, risk 0): For sale - arsenal dartboard. Good condition but no doubles or trebles!
- MISSED (No obvious threat detected, risk 0): Your weekly Cool-Mob tones are ready to download !This weeks new Tones include: 1) Crazy Frog-AXEL F>>> 2) Akon-Lonely>>> 3) Black Eyed-Dont P >>>More info in n
- MISSED (No obvious threat detected, risk 0): Email AlertFrom: Jeri StewartSize: 2KBSubject: Low-cost prescripiton drvgsTo listen to email call 123
- MISSED (No obvious threat detected, risk 8): Marvel Mobile Play the official Ultimate Spider-man game (£4.50) on ur mobile right now. Text SPIDER to 83338 for the game & we ll send u a FREE 8Ball wallpaper
- MISSED (No obvious threat detected, risk 9): FreeMsg>FAV XMAS TONES!Reply REAL
- MISSED (No obvious threat detected, risk 7): 1000's of girls many local 2 u who r virgins 2 this & r ready 2 4fil ur every sexual need. Can u 4fil theirs? text CUTE to 69911(£1.50p. m)
- MISSED (No obvious threat detected, risk 8): Mobile Club: Choose any of the top quality items for your mobile. 7cfca1a
- MISSED (No obvious threat detected, risk 7): I want some cock! My hubby's away, I need a real man 2 satisfy me. Txt WIFE to 89938 for no strings action. (Txt STOP 2 end, txt rec £1.50ea. OTBox 731 LA1 7WS.
- MISSED (No obvious threat detected, risk 0): XCLUSIVE@CLUBSAISAI 2MOROW 28/5 SOIREE SPECIALE ZOUK WITH NICHOLS FROM PARIS.FREE ROSES 2 ALL LADIES !!! info: 07946746291/07880867867 
- MISSED (No obvious threat detected, risk 8): Download as many ringtones as u like no restrictions, 1000s 2 choose. U can even send 2 yr buddys. Txt Sir to 80082 £3 
- MISSED (No obvious threat detected, risk 0): ROMCAPspam Everyone around should be responding well to your presence since you are so warm and outgoing. You are bringing in a real breath of sunshine.
- MISSED (No obvious threat detected, risk 0): Do you realize that in about 40 years, we'll have thousands of old ladies running around with tattoos?
- MISSED (No obvious threat detected, risk 0): RCT' THNQ Adrian for U text. Rgds Vatian
- MISSED (No obvious threat detected, risk 0): Hi ya babe x u 4goten bout me?' scammers getting smart..Though this is a regular vodafone no, if you respond you get further prem rate msg/subscription. Other n

**Risk score thresholds** (full system): what would happen if a single cut-off were used instead of the verdict rules.

| Flag when risk score >= | Precision | Recall | FPR | FNR | F1 | TP/FP/FN/TN |
|---|---|---|---|---|---|---|
| 10 | 0.98 (0.94-1.00) | 0.83 (0.76-0.88) | 0.00 (0.00-0.01) | 0.17 (0.12-0.24) | 0.90 | 124/2/25/964 |
| 20 | 0.93 (0.78-0.98) | 0.18 (0.13-0.25) | 0.00 (0.00-0.01) | 0.82 (0.75-0.87) | 0.30 | 27/2/122/964 |
| 30 | 0.93 (0.77-0.98) | 0.17 (0.12-0.24) | 0.00 (0.00-0.01) | 0.83 (0.76-0.88) | 0.29 | 26/2/123/964 |
| 40 | 0.93 (0.70-0.99) | 0.09 (0.06-0.15) | 0.00 (0.00-0.01) | 0.91 (0.85-0.94) | 0.17 | 14/1/135/965 |
| 50 | 0.00 (0.00-0.79) | 0.00 (0.00-0.03) | 0.00 (0.00-0.01) | 1.00 (0.97-1.00) | 0.00 | 0/1/149/965 |
| 60 | n/a | 0.00 (0.00-0.03) | 0.00 (0.00-0.00) | 1.00 (0.97-1.00) | 0.00 | 0/0/149/966 |
| 70 | n/a | 0.00 (0.00-0.03) | 0.00 (0.00-0.00) | 1.00 (0.97-1.00) | 0.00 | 0/0/149/966 |

## D. Design check: letting the ML model warn on its own

With no known tactic, should very scam-like wording (model output >= 0.9) be enough for "Be careful", or only "Insufficient information"? Both counted at the cautious operating point. The app uses "Be careful" because it cuts false negatives without adding false positives here.

| Test set | Design | Precision | Recall | FPR | FNR | F1 | TP/FP/FN/TN |
|---|---|---|---|---|---|---|---|
| Modern | model only corroborates | 1.00 (0.95-1.00) | 0.97 (0.91-0.99) | 0.00 (0.00-0.06) | 0.03 (0.01-0.09) | 0.99 | 71/0/2/66 |
| Modern | model may warn alone (used) | 1.00 (0.95-1.00) | 0.97 (0.91-0.99) | 0.00 (0.00-0.06) | 0.03 (0.01-0.09) | 0.99 | 71/0/2/66 |
| 2012 SMS | model only corroborates | 0.93 (0.79-0.98) | 0.19 (0.13-0.26) | 0.00 (0.00-0.01) | 0.81 (0.74-0.87) | 0.31 | 28/2/121/964 |
| 2012 SMS | model may warn alone (used) | 0.98 (0.94-1.00) | 0.83 (0.76-0.88) | 0.00 (0.00-0.01) | 0.17 (0.12-0.24) | 0.90 | 124/2/25/964 |

## E. Conversations: last message only vs whole conversation

24 hand-written chats (14 scams, 10 genuine look-alikes such as an old schoolfriend's 'is this Rahul?' or a parent asking for money). Uses the final trained model; no conversation was used for training.

| Judged on | Flagged when | Precision | Recall | FPR | FNR | F1 | TP/FP/FN/TN |
|---|---|---|---|---|---|---|---|
| Last message only | cautious | 1.00 (0.76-1.00) | 0.86 (0.60-0.96) | 0.00 (0.00-0.28) | 0.14 (0.04-0.40) | 0.92 | 12/0/2/10 |
| Whole conversation | cautious | 1.00 (0.78-1.00) | 1.00 (0.78-1.00) | 0.00 (0.00-0.28) | 0.00 (0.00-0.22) | 1.00 | 14/0/0/10 |

Dangerous misses (scam labelled "No obvious threat detected"):

- Last message only: 2 (pig_butchering_subtle, hi_mum_subtle)
- Whole conversation: 0

| Chat | Label | Last message only | Whole conversation |
|---|---|---|---|
| pig_butchering | scam | Likely a scam | Likely a scam |
| romance_customs | scam | Likely a scam | Likely a scam |
| task_job | scam | Likely a scam | Likely a scam |
| army_buyer | scam | Likely a scam | Likely a scam |
| fake_customer_care | scam | Likely a scam | Likely a scam |
| hi_mum | scam | Likely a scam | Likely a scam |
| digital_arrest | scam | Be careful | Likely a scam |
| electricity_apk | scam | Likely a scam | Likely a scam |
| investment_group | scam | Likely a scam | Likely a scam |
| sextortion | scam | Likely a scam | Likely a scam |
| pig_butchering_subtle | scam | No obvious threat detected | Likely a scam |
| hi_mum_subtle | scam | No obvious threat detected | Likely a scam |
| qr_refund_subtle | scam | Be careful | Likely a scam |
| job_subtle | scam | Be careful | Likely a scam |
| old_friend | safe | No obvious threat detected | No obvious threat detected |
| dance_class | safe | No obvious threat detected | No obvious threat detected |
| family_books | safe | No obvious threat detected | No obvious threat detected |
| split_bill | safe | No obvious threat detected | No obvious threat detected |
| landlord | safe | No obvious threat detected | No obvious threat detected |
| colleague_deadline | safe | No obvious threat detected | No obvious threat detected |
| delivery | safe | No obvious threat detected | No obvious threat detected |
| bank_support | safe | No obvious threat detected | No obvious threat detected |
| school_pickup | safe | No obvious threat detected | No obvious threat detected |
| olx_genuine_buyer | safe | No obvious threat detected | No obvious threat detected |

## F. Confidence calibration: is "High" confidence really more reliable?

All test sets combined (modern messages with the cross-validated model, 2012 SMS held out, and the conversations). If confidence is meaningful, accuracy should fall from High to Medium to Low.

| Confidence | Messages | Right | Wrong | Undecided | Right answers | Wrong answers |
|---|---|---|---|---|---|---|
| High | 498 | 494 | 4 | 0 | 0.99 (0.98-1.00) | 0.01 (0.00-0.02) |
| Medium | 619 | 597 | 22 | 0 | 0.96 (0.95-0.98) | 0.04 (0.02-0.05) |
| Low | 161 | 115 | 0 | 46 | 0.71 (0.64-0.78) | 0.00 (0.00-0.02) |

"Right answers" counts an undecided verdict as not right: Low confidence is mostly "Insufficient information" and hedged "Be careful" answers, which is the point of being unsure.

The share of right answers falls from High to Medium to Low, as it should.

