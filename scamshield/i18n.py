"""Short spoken and written verdicts in Indian languages, for voice output.

These work without an API key, so an elderly user can hear the verdict in
their language even when the AI explanation isn't set up. They're kept short
and fixed on purpose: a few sentences checked once are safer than generated
text. NOTE: translations should be reviewed by native speakers before wide use.
"""
from __future__ import annotations

from .risk import CAREFUL, SAFE, SCAM, UNSURE

# BCP-47 codes for the browser's speech synthesis voices.
VOICE_CODES = {"English": "en-IN", "Hindi": "hi-IN", "Kannada": "kn-IN", "Tamil": "ta-IN", "Telugu": "te-IN",
               "Malayalam": "ml-IN", "Marathi": "mr-IN", "Bengali": "bn-IN"}

PHRASES = {
    "English": {
        SCAM: "This message looks like a scam.",
        CAREFUL: "This message has warning signs. Be careful.",
        SAFE: "We didn't find any clear signs of a scam in this message.",
        UNSURE: "We can't say for sure whether this is a scam.",
        "dont": "Don't click any links, don't send money, and don't tell anyone your OTP or PIN.",
        "check": "Talk to someone you trust before you do anything.",
        "paid": "If you have already sent money, call 1930 now and tell your bank.",
    },
    "Hindi": {
        SCAM: "यह संदेश धोखाधड़ी लगता है।",
        CAREFUL: "इस संदेश में खतरे के संकेत हैं। सावधान रहें।",
        SAFE: "इस संदेश में धोखाधड़ी का कोई साफ़ संकेत नहीं मिला।",
        UNSURE: "हम पक्का नहीं कह सकते कि यह धोखाधड़ी है या नहीं।",
        "dont": "किसी लिंक पर क्लिक न करें, पैसे न भेजें, और अपना OTP या PIN किसी को न बताएं।",
        "check": "कुछ भी करने से पहले किसी भरोसेमंद व्यक्ति से बात करें।",
        "paid": "अगर आपने पैसे भेज दिए हैं, तो तुरंत 1930 पर कॉल करें और अपने बैंक को बताएं।",
    },
    "Kannada": {
        SCAM: "ಈ ಸಂದೇಶ ವಂಚನೆಯಂತೆ ಕಾಣುತ್ತದೆ.",
        CAREFUL: "ಈ ಸಂದೇಶದಲ್ಲಿ ಎಚ್ಚರಿಕೆಯ ಸೂಚನೆಗಳಿವೆ. ಜಾಗರೂಕರಾಗಿರಿ.",
        SAFE: "ಈ ಸಂದೇಶದಲ್ಲಿ ವಂಚನೆಯ ಸ್ಪಷ್ಟ ಸೂಚನೆ ಕಂಡುಬಂದಿಲ್ಲ.",
        UNSURE: "ಇದು ವಂಚನೆಯೇ ಅಲ್ಲವೇ ಎಂದು ಖಚಿತವಾಗಿ ಹೇಳಲು ಸಾಧ್ಯವಿಲ್ಲ.",
        "dont": "ಯಾವುದೇ ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ, ಹಣ ಕಳುಹಿಸಬೇಡಿ, ನಿಮ್ಮ OTP ಅಥವಾ PIN ಅನ್ನು ಯಾರಿಗೂ ಹೇಳಬೇಡಿ.",
        "check": "ಏನಾದರೂ ಮಾಡುವ ಮೊದಲು ನಂಬಿಕಸ್ಥ ವ್ಯಕ್ತಿಯೊಂದಿಗೆ ಮಾತನಾಡಿ.",
        "paid": "ನೀವು ಈಗಾಗಲೇ ಹಣ ಕಳುಹಿಸಿದ್ದರೆ, ತಕ್ಷಣ 1930 ಗೆ ಕರೆ ಮಾಡಿ ಮತ್ತು ನಿಮ್ಮ ಬ್ಯಾಂಕಿಗೆ ತಿಳಿಸಿ.",
    },
    "Tamil": {
        SCAM: "இந்தச் செய்தி ஒரு மோசடி போல் தெரிகிறது.",
        CAREFUL: "இந்தச் செய்தியில் எச்சரிக்கை அறிகுறிகள் உள்ளன. கவனமாக இருங்கள்.",
        SAFE: "இந்தச் செய்தியில் மோசடிக்கான தெளிவான அறிகுறி எதுவும் இல்லை.",
        UNSURE: "இது மோசடியா இல்லையா என்று உறுதியாகச் சொல்ல முடியவில்லை.",
        "dont": "எந்த இணைப்பையும் கிளிக் செய்யாதீர்கள், பணம் அனுப்பாதீர்கள், உங்கள் OTP அல்லது PIN-ஐ யாரிடமும் சொல்லாதீர்கள்.",
        "check": "எதையும் செய்வதற்கு முன் நம்பகமான ஒருவரிடம் பேசுங்கள்.",
        "paid": "நீங்கள் ஏற்கனவே பணம் அனுப்பியிருந்தால், உடனே 1930-க்கு அழைத்து உங்கள் வங்கிக்குத் தெரிவியுங்கள்.",
    },
    "Telugu": {
        SCAM: "ఈ సందేశం మోసంలా కనిపిస్తోంది.",
        CAREFUL: "ఈ సందేశంలో హెచ్చరిక సంకేతాలు ఉన్నాయి. జాగ్రత్తగా ఉండండి.",
        SAFE: "ఈ సందేశంలో మోసానికి సంబంధించిన స్పష్టమైన సంకేతం ఏదీ కనిపించలేదు.",
        UNSURE: "ఇది మోసమో కాదో ఖచ్చితంగా చెప్పలేము.",
        "dont": "ఏ లింక్‌నూ క్లిక్ చేయకండి, డబ్బు పంపకండి, మీ OTP లేదా PIN ఎవరికీ చెప్పకండి.",
        "check": "ఏదైనా చేసే ముందు మీకు నమ్మకమైన వ్యక్తితో మాట్లాడండి.",
        "paid": "మీరు ఇప్పటికే డబ్బు పంపి ఉంటే, వెంటనే 1930 కి కాల్ చేసి మీ బ్యాంకుకు తెలియజేయండి.",
    },
    "Malayalam": {
        SCAM: "ഈ സന്ദേശം ഒരു തട്ടിപ്പ് പോലെ തോന്നുന്നു.",
        CAREFUL: "ഈ സന്ദേശത്തിൽ മുന്നറിയിപ്പ് സൂചനകളുണ്ട്. ശ്രദ്ധിക്കുക.",
        SAFE: "ഈ സന്ദേശത്തിൽ തട്ടിപ്പിന്റെ വ്യക്തമായ സൂചനയൊന്നും കണ്ടെത്തിയില്ല.",
        UNSURE: "ഇത് തട്ടിപ്പാണോ അല്ലയോ എന്ന് ഉറപ്പിച്ചു പറയാൻ കഴിയില്ല.",
        "dont": "ഒരു ലിങ്കിലും ക്ലിക്ക് ചെയ്യരുത്, പണം അയയ്ക്കരുത്, നിങ്ങളുടെ OTP-യോ PIN-ഓ ആരോടും പറയരുത്.",
        "check": "എന്തെങ്കിലും ചെയ്യുന്നതിന് മുമ്പ് വിശ്വസ്തനായ ഒരാളോട് സംസാരിക്കുക.",
        "paid": "നിങ്ങൾ ഇതിനകം പണം അയച്ചിട്ടുണ്ടെങ്കിൽ, ഉടൻ 1930-ൽ വിളിച്ച് നിങ്ങളുടെ ബാങ്കിനെ അറിയിക്കുക.",
    },
    "Marathi": {
        SCAM: "हा संदेश फसवणूक असल्यासारखा वाटतो.",
        CAREFUL: "या संदेशात धोक्याची चिन्हे आहेत. सावध राहा.",
        SAFE: "या संदेशात फसवणुकीचे कोणतेही स्पष्ट चिन्ह आढळले नाही.",
        UNSURE: "ही फसवणूक आहे की नाही हे आम्ही खात्रीने सांगू शकत नाही.",
        "dont": "कोणत्याही लिंकवर क्लिक करू नका, पैसे पाठवू नका आणि तुमचा OTP किंवा PIN कोणालाही सांगू नका.",
        "check": "काहीही करण्यापूर्वी विश्वासू व्यक्तीशी बोला.",
        "paid": "तुम्ही आधीच पैसे पाठवले असतील तर लगेच 1930 वर कॉल करा आणि तुमच्या बँकेला कळवा.",
    },
    "Bengali": {
        SCAM: "এই বার্তাটি প্রতারণা বলে মনে হচ্ছে।",
        CAREFUL: "এই বার্তায় সতর্কতার লক্ষণ আছে। সাবধান থাকুন।",
        SAFE: "এই বার্তায় প্রতারণার কোনো স্পষ্ট লক্ষণ পাওয়া যায়নি।",
        UNSURE: "এটি প্রতারণা কি না, আমরা নিশ্চিতভাবে বলতে পারছি না।",
        "dont": "কোনো লিংকে ক্লিক করবেন না, টাকা পাঠাবেন না, এবং আপনার OTP বা PIN কাউকে বলবেন না।",
        "check": "কিছু করার আগে বিশ্বস্ত কারও সাথে কথা বলুন।",
        "paid": "আপনি যদি ইতিমধ্যে টাকা পাঠিয়ে থাকেন, এখনই 1930-এ কল করুন এবং আপনার ব্যাংককে জানান।",
    },
}


def spoken_summary(verdict: str, language: str) -> str:
    """A short, fixed summary of the verdict in the chosen language."""
    p = PHRASES.get(language, PHRASES["English"])
    parts = [p[verdict]]
    if verdict in (SCAM, CAREFUL):
        parts += [p["dont"], p["paid"]]
    elif verdict == UNSURE:
        parts += [p["dont"], p["check"]]
    return " ".join(parts)
