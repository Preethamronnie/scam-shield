import pytest

from scamshield import analyze
from scamshield.analyzer import SAFE, SCAM
from scamshield.signals import find_signals


def ids(text):
    return {s.id for s in find_signals(text)}


@pytest.mark.parametrize("text,flag", [
    ("Please share the OTP you received to stop the transaction", "asks_secret"),
    ("To receive Rs 5000 enter your UPI PIN", "pin_to_receive"),
    ("Install AnyDesk so we can fix your computer", "remote_access"),
    ("You won a lucky draw! Pay the processing fee to claim", "fee_for_prize"),
    ("Hi Mum, this is my new number", "new_number_family"),
    ("Earn Rs 3000 daily from home by liking videos", "easy_job"),
    ("Verify at http://sbi-secure.example.xyz now", "fake_brand_link"),
])
def test_red_flags(text, flag):
    assert flag in ids(text)


def test_real_otp_notice_is_not_flagged_as_asking_for_otp():
    assert "asks_secret" not in ids("123456 is your OTP. Do not share it with anyone.")


@pytest.mark.parametrize("text", [
    "Dear customer, your KYC has expired. Share the OTP you receive with our executive to avoid account block.",
    "You have received Rs 2,000. Enter your UPI PIN to accept the money.",
])
def test_obvious_scams(text):
    assert analyze(text).verdict == SCAM


@pytest.mark.parametrize("text", [
    "Are we still meeting for lunch on Sunday?",
    "Your appointment is confirmed for Monday at 10am.",
])
def test_everyday_messages(text):
    assert analyze(text).verdict == SAFE


def test_empty_message():
    with pytest.raises(ValueError):
        analyze("   ")


@pytest.mark.parametrize("text,flag", [
    ("Download the SBI Rewards app from this link: sbi-rewards.apk", "apk_file"),
    ("You are under digital arrest. Stay on the video call.", "digital_arrest"),
    ("Mummy I had an accident, please send Rs 50,000 on UPI", "emergency_money"),
    ("Pay Rs 25,000 or I will share the video with your family", "sextortion"),
    ("I sent Rs 5,000 to you by mistake, please return it", "sent_by_mistake"),
    ("Your credit card reward points expire today", "reward_points"),
    ("Upgrade your SIM to eSIM 5G, reply with the code we sent", "sim_swap"),
    ("Earn Rs 150 for every hotel review on Google Maps", "job_task_fee"),
])
def test_current_scam_types(text, flag):
    assert flag in ids(text)


def test_red_flags_survive_line_breaks():
    # Text read from a screenshot is split into lines mid-sentence.
    assert "reward_points" in ids("your SBI reward\npoints will expire\ntoday")


def test_photo_text_extraction(tmp_path):
    from PIL import Image, ImageDraw, ImageFont
    from scamshield import ocr

    if not ocr.available():
        pytest.skip("no OCR engine installed")
    im = Image.new("RGB", (900, 200), "white")
    ImageDraw.Draw(im).text((20, 60), "Share your OTP to unblock your account",
                            fill="black", font=ImageFont.load_default(size=40))
    path = tmp_path / "msg.png"
    im.save(path)
    text, _ = ocr.extract_text(path.read_bytes())
    assert "otp" in text.lower()
