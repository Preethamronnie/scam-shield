"""Downloads the UCI SMS Spam Collection into data/sms.tsv."""
import urllib.request

from scamshield.data import DATA, SMS_URL

if __name__ == "__main__":
    DATA.mkdir(exist_ok=True)
    out = DATA / "sms.tsv"
    urllib.request.urlretrieve(SMS_URL, out)
    print(f"saved {out}")
