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
