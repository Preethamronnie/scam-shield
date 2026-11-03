"""Scam phrases in Hindi: romanised (Hinglish) and Devanagari.

Many Indians write Hindi in English letters ("OTP batao", "khata band ho
jayega"), and many scams are written that way too. The English rules can't
see these, so this module adds native patterns for the most common scam
tactics. Each pattern produces the *same* red flag as the matching English
rule (same ID, category and explanation), quoting the original words.

Important: this is detection in the language itself, not translation. It
covers common scam phrases only, not Hindi in general. The app reports Hindi
support as "partial", lowers confidence for it, and for other Indian
languages it says plainly that it can't judge (see preprocess.Language).

Python's \\b doesn't work inside Devanagari words (vowel signs aren't
"word" characters), so Devanagari patterns avoid it.
"""
from __future__ import annotations

import re

# Romanised Hindi spelling varies a lot; these cover the usual forms.
_TELL = r"(batao|bataiye|bataie|batayein|batayen|bata do|bata dijiye|bolo|boliye|bhejo|bhej do|bhejiye|share karo|share kar do|share kijiye|forward karo|forward kar do|de do|dedo|dijiye|daalo|dalo)"
_SEND = r"(bhejo|bhej do|bhej dijiye|bhejiye|bhejna|transfer karo|transfer kar do|transfer kijiye|daal do|dal do|jama karo|jama kar do|pay karo|pay kar do|bhar do|bharo)"
# Money: a money word, or an amount of at least 1,000 (so "500 bhej do auto ke liye"
# from a parent isn't treated like "20000 bhej do").
_MONEY = r"(paise|paisa|pese|rupaye|rupay|rupees|rs\.?|₹|upi|\d{1,3}(?:,\d{3})+|\d{4,})"

HINGLISH = [
    ("asks_secret", 0.95, rf"\b(otp|pin|password|passcode|code|cvv)\b.{{0,40}}\b{_TELL}\b|\b{_TELL}\b.{{0,30}}\b(otp|pin|code)\b"),
    ("threat", 0.7, r"\b(khata|khaata|account|sim|number|bijli|connection|card|kyc|upi)\b.{0,40}\b(band|bandh|block|blocked|kat|cut|suspend|freeze|deactivate)\b"
                    r"|\b(giraftar|giraftaar|arrest)\b"),
    ("urgency", 0.3, r"\b(turant|turat|jaldi|fauran|foran|aaj hi|abhi ke abhi|\d+ ghante)\b"),
    ("money_request", 0.55, rf"\b{_MONEY}.{{0,30}}\b{_SEND}\b|\b{_SEND}\b.{{0,30}}{_MONEY}"),
    ("secrecy", 0.7, r"\b(kisi ko|kisiko|ghar (par|pe|mein)|papa ko|mummy ko|family ko|gharwalon ko)\b.{0,20}\b(mat|na|nahi)\b.{0,5}\b(batana|bataana|batao|bolna|kehna)\b"),
    ("new_number_family", 0.75, r"\b(naya number|new number|phone (kho|gir|toot|tut|kharab|kharaab) (gaya|gya|ho gaya))\b"),
    ("emergency_money", 0.85, rf"\b(accident|hospital|aspatal|giraftar|thane|police station|jail)\b.{{0,80}}({_MONEY}|\b{_SEND}\b)"),
    ("digital_arrest", 0.9, r"\bdigital (arrest|giraftar|giraftari)\b"
                            r"|\b(cbi|police|customs|crime branch|cyber crime|ncb|ed)\b.{0,80}\b(case|warrant|giraftar|giraftaar|video call)\b"),
    ("prize", 0.6, r"\b(lottery|inaam|inam|jeet gaye|jeet liya|jeeta|lucky draw|kbc)\b"),
    ("fee_for_prize", 0.9, r"\b(inaam|inam|lottery|prize|naukri|job|loan|parcel)\b.{0,80}\b(fees|fee|charge|shulk|processing)\b"),
    ("sent_by_mistake", 0.8, r"\b(galti se|galati se|by mistake)\b.{0,60}\b(bhej|transfer|aa gaye|chale gaye|aagaye)\w*.{0,60}\b(wapas|vapas|lauta|return)\w*"),
    ("pin_to_receive", 0.95, r"\b(paise|paisa|refund|cashback|inaam)\b.{0,40}\b(lene|paane|receive|prapt)\b.{0,30}\b(pin|upi pin|scan)\b"),
    ("easy_job", 0.75, r"\b(ghar baithe|work from home|part time)\b.{0,60}\b(kamao|kamaye|kamaiye|kamai|earn|rozana|roz)\b"),
]

DEVANAGARI = [
    ("asks_secret", 0.95, r"(ओटीपी|otp|ओ\.टी\.पी|पिन|पासवर्ड|कोड).{0,40}(बताएं|बताएँ|बताइए|बताओ|बता दें|बता दीजिए|भेजें|भेजो|भेज दें|शेयर करें|शेयर कर दें|दें|दीजिए)"),
    ("threat", 0.7, r"(खाता|अकाउंट|सिम|नंबर|बिजली|कनेक्शन|कार्ड|केवाईसी|यूपीआई).{0,40}(बंद|ब्लॉक|काट|निलंबित|फ्रीज)|(गिरफ्तार|गिरफ़्तार)"),
    ("urgency", 0.3, r"(तुरंत|जल्दी|फौरन|आज ही|अभी के अभी|\d+ घंटे)"),
    ("money_request", 0.55, r"(पैसे|रुपये|रुपए|₹|\d{1,3}(?:,\d{3})+|\d{4,}).{0,30}(भेजें|भेजो|भेज दो|भेज दें|भेज दीजिए|ट्रांसफर|जमा करें|डाल दो)"
                            r"|(भेजें|भेजो|भेज दो|भेज दीजिए|ट्रांसफर करें).{0,30}(पैसे|रुपये|रुपए|₹|\d{1,3}(?:,\d{3})+|\d{4,})"),
    ("secrecy", 0.7, r"(किसी को|घर में|पापा को|मम्मी को|परिवार को).{0,20}(मत|न|नहीं).{0,5}(बताना|बताएं|बताइए|बोलना|कहना)"),
    ("new_number_family", 0.75, r"(नया नंबर|फ़ोन खो गया|फोन खो गया|फोन टूट गया|फ़ोन टूट गया|फोन गिर गया)"),
    ("emergency_money", 0.85, r"(दुर्घटना|एक्सीडेंट|अस्पताल|हॉस्पिटल|गिरफ्तार|थाने|जेल).{0,80}(पैसे|रुपये|भेज|ट्रांसफर)"),
    ("digital_arrest", 0.9, r"(डिजिटल अरेस्ट|डिजिटल गिरफ्तारी)|(सीबीआई|पुलिस|कस्टम्स|क्राइम ब्रांच|साइबर क्राइम).{0,80}(केस|मामला|वारंट|गिरफ्तार|वीडियो कॉल)"),
    ("prize", 0.6, r"(लॉटरी|इनाम|जीत गए|जीत लिया|लकी ड्रा|केबीसी)"),
    ("fee_for_prize", 0.9, r"(इनाम|लॉटरी|नौकरी|लोन|पार्सल).{0,80}(शुल्क|फीस|चार्ज|प्रोसेसिंग)"),
    ("sent_by_mistake", 0.8, r"(गलती से|ग़लती से).{0,60}(भेज|ट्रांसफर).{0,60}(वापस|लौटा)"),
    ("pin_to_receive", 0.95, r"(पैसे|रिफंड|कैशबैक|इनाम).{0,40}(पाने|लेने|प्राप्त).{0,30}(पिन|स्कैन)"),
    ("easy_job", 0.75, r"(घर बैठे|वर्क फ्रॉम होम|पार्ट टाइम).{0,60}(कमाएं|कमाइए|कमाओ|कमाई|रोज़ाना|रोजाना)"),
]

COMPILED = ([(sid, w, re.compile(p, re.I | re.S), "Hinglish") for sid, w, p in HINGLISH]
            + [(sid, w, re.compile(p, re.S), "Hindi") for sid, w, p in DEVANAGARI])
COVERED_TACTICS = sorted({sid for sid, *_ in COMPILED})
