"""Writes data/conversations.json: hand-written chats for testing the context
engine. Each scam is paired in spirit with a genuine chat that looks similar
on the surface (a "wrong number" that's really an old schoolfriend, a money
request that's really from family). All names and numbers are made up."""
import json
from pathlib import Path

SCAM, SAFE = "scam", "safe"

CONVERSATIONS = [
    (SCAM, "pig_butchering", [
        ("Priya", "Hi, is this Ananya?"), ("You", "No, wrong number"),
        ("Priya", "Oh sorry! You seem nice though. Where are you from?"), ("You", "Bangalore"),
        ("Priya", "I work in fashion in Singapore. My uncle is a crypto mentor, he helped me earn 40% profit last week"),
        ("Priya", "You can join our VIP trading group too. Just deposit Rs 10,000 to start")]),
    (SCAM, "romance_customs", [
        ("David", "Good morning dear, how are you today?"), ("You", "I'm fine"),
        ("David", "I work as a doctor in the UK. I feel we have a special connection"),
        ("David", "I have sent you a gift parcel with gold and an iPhone"),
        ("David", "The customs office says you must pay Rs 35,000 clearance charge to release it. Please pay today")]),
    (SCAM, "task_job", [
        ("Riya HR", "Hello, are you looking for part time work? Nice to meet you"), ("You", "Maybe, what is it?"),
        ("Riya HR", "Simple tasks, like YouTube videos and earn Rs 50 each. Daily payout"),
        ("You", "OK I did 3 tasks"), ("Riya HR", "Great! Now this is a bonus task. Deposit Rs 5,000 to unlock your commission")]),
    (SCAM, "army_buyer", [
        ("Vikram", "Is the sofa still available?"), ("You", "Yes"),
        ("Vikram", "I am in the army, posted at the airport. I will buy it, no need to see"),
        ("Vikram", "I will send payment by QR code. Just scan it and enter your PIN to receive the money")]),
    (SCAM, "fake_customer_care", [
        ("Amit", "Hello sir, I am from Amazon customer care. Your refund of Rs 4,999 is pending."), ("You", "OK"),
        ("Amit", "Please share the OTP you received to process the refund"), ("You", "No, I'm not sharing that"),
        ("Amit", "Sir it is urgent, refund will expire today. Just tell me the OTP")]),
    (SCAM, "hi_mum", [
        ("Unknown", "Hi Mum, it's me, I dropped my phone. This is my new number"), ("Me", "Oh no! Are you ok?"),
        ("Unknown", "Yes but I can't talk right now"),
        ("Unknown", "I need to pay a bill urgently and my bank app isn't working. Can you send Rs 18,000 to this UPI ID? riya.pay@ybl")]),
    (SCAM, "digital_arrest", [
        ("FedEx Support", "Your parcel to Taiwan was stopped. It contains drugs and fake passports."),
        ("You", "That's not mine"),
        ("FedEx Support", "I am transferring your call to Mumbai Cyber Crime. Stay on the video call"),
        ("Inspector Sharma", "A case is registered against you for money laundering. You are under digital arrest. Do not tell your family"),
        ("Inspector Sharma", "Transfer your savings to the RBI verification account to prove your innocence")]),
    (SCAM, "electricity_apk", [
        ("Electricity Office", "Dear consumer, your last month bill is not updated"), ("You", "I paid it"),
        ("Electricity Office", "Your power connection will be disconnected tonight at 9:30pm"),
        ("Electricity Office", "To update, download the app from this link: bill-update.apk")]),
    (SCAM, "investment_group", [
        ("Kiran", "Hey! Long time. Added you to a stock tips group, it's really good"), ("You", "Thanks, what is it?"),
        ("Kiran", "Our professor gives IPO allotment tips. Guaranteed returns, 300% in a month"),
        ("Kiran", "To withdraw profit you just pay the 10% tax first. Download our institutional trading app")]),
    (SCAM, "sextortion", [
        ("Sonia", "Hi, nice to chat with you. Are you single?"), ("You", "Haha yes"),
        ("Sonia", "Let's do a video call"),
        ("Sonia", "I have recorded the video call with you. Pay Rs 25,000 or I will send the video to all your family and friends")]),

    # Harder cases: the last message on its own looks harmless; the request came earlier.
    (SCAM, "pig_butchering_subtle", [
        ("Meera", "Hello, is this Dr. Gupta's clinic?"), ("You", "No, wrong number"),
        ("Meera", "So sorry! You seem kind. I live in Dubai, what do you do?"), ("You", "I'm an engineer"),
        ("Meera", "Nice! My mentor taught me crypto trading, I made 40% profit last month on the app"),
        ("Meera", "Shall I add you to the group? You can see the results yourself first")]),
    (SCAM, "hi_mum_subtle", [
        ("Unknown", "Hi Dad, my phone broke so this is my new number. Please save it"), ("Me", "Ok beta"),
        ("Unknown", "Can you send Rs 25,000 for my college fees? The office closes today"), ("Me", "Why so sudden?"),
        ("Unknown", "Please Dad, I'll explain everything later. Can you do it now?")]),
    (SCAM, "qr_refund_subtle", [
        ("Ravi", "Hello, I sent you Rs 5,000 by mistake on PhonePe. Please return it"), ("You", "I didn't get anything"),
        ("Ravi", "I am sending a QR code, scan it and enter your PIN to receive the refund back"),
        ("Ravi", "Did you do it? Please, it was my mother's hospital money")]),
    (SCAM, "job_subtle", [
        ("Anjali HR", "Hi, nice to meet you. I'm Anjali, a recruiter. We have work from home openings"),
        ("You", "What is the salary?"),
        ("Anjali HR", "You earn Rs 3,000 daily by rating hotels on Google Maps. Registration fee is Rs 1,999"),
        ("Anjali HR", "Let me know by today, only 5 seats left")]),

    (SAFE, "old_friend", [
        ("Arjun", "Hi, is this Rahul? This is Arjun from school, got your number from Vinay"),
        ("You", "Arjun! How are you?"), ("Arjun", "Good! I'm in Bangalore now, working in a startup"),
        ("Arjun", "Let's meet for coffee this weekend? Saturday at 5 near MG Road")]),
    (SAFE, "dance_class", [
        ("Neha", "Hi! Is this Kavya's number?"), ("You", "Yes, who is this?"),
        ("Neha", "Neha from the dance class, got it from the group"), ("You", "Oh hi Neha!"),
        ("Neha", "Are you coming to practice on Saturday? It's at 10")]),
    (SAFE, "family_books", [
        ("Mom", "Did you reach the hostel?"), ("Me", "Yes just now"),
        ("Mom", "Good. I've sent you Rs 2,000 for the books, tell me if you got it"), ("Me", "Got it, thanks mom")]),
    (SAFE, "split_bill", [
        ("Sameer", "Dinner was fun yesterday!"), ("You", "Yes! What was my share?"),
        ("Sameer", "Rs 450 each. Send it on GPay whenever you're free, no hurry")]),
    (SAFE, "landlord", [
        ("Mr Rao", "Good morning. Reminder that rent for November is due on the 5th"),
        ("You", "Sure, same account as before?"),
        ("Mr Rao", "Yes, same UPI ID as always. Please send the receipt once paid")]),
    (SAFE, "colleague_deadline", [
        ("Divya", "Hey, the client report is due today"), ("You", "I'm on it"),
        ("Divya", "Thanks! Please send it to me by 5 so I can review before it goes out. It's urgent")]),
    (SAFE, "delivery", [
        ("Delivery Partner", "Hello, I am outside with your Flipkart order. Which floor?"), ("You", "3rd floor, flat 302"),
        ("Delivery Partner", "Coming up. Please keep the delivery OTP ready, I will ask for it when you receive the package")]),
    (SAFE, "bank_support", [
        ("HDFC Bank", "Thank you for contacting HDFC Bank. Your complaint number is 4521."), ("You", "When will my card arrive?"),
        ("HDFC Bank", "Your card was dispatched on 2 Nov and should reach you in 5 working days. We will never ask for your OTP or PIN")]),
    (SAFE, "school_pickup", [
        ("Dad", "Can you pick up Anu from school today? I'm stuck in a meeting"), ("You", "What time?"),
        ("Dad", "At 3:30, please be on time. My phone battery is low so I may not reply")]),
    (SAFE, "olx_genuine_buyer", [
        ("Pooja", "Hi, is the study table still available?"), ("You", "Yes"),
        ("Pooja", "Can I come see it tomorrow evening? I'll pay cash when I pick it up")]),
]


def as_text(turns) -> str:
    return "\n".join(f"{who}: {text}" for who, text in turns)


if __name__ == "__main__":
    out = Path(__file__).resolve().parents[1] / "data" / "conversations.json"
    data = [{"label": lab, "id": cid, "text": as_text(turns)} for lab, cid, turns in CONVERSATIONS]
    out.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {len(data)} conversations to {out}")
