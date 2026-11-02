"""Human review of user feedback. Nothing reaches training without this step.

    python -m scripts.review_feedback

For each pending report that includes (masked) message text, the reviewer
decides the true label. Approved items go to data/reviewed_examples.csv with
their provenance; rejected ones are kept as rejected so they aren't reviewed
again. Reports without text are only counted (they're useful for spotting
which rules cause complaints, but can't become training examples).
"""
import csv
import json
from collections import Counter
from datetime import date
from pathlib import Path

from scamshield.feedback import feedback_dir

REVIEWED = Path(__file__).resolve().parents[1] / "data" / "reviewed_examples.csv"


def main():
    pending = feedback_dir() / "pending.jsonl"
    if not pending.exists():
        print("No feedback yet.")
        return
    items = [json.loads(line) for line in pending.read_text(encoding="utf-8").splitlines() if line.strip()]
    todo = [i for i in items if i["status"] == "pending"]
    print("Reports by kind:", dict(Counter(i["kind"] for i in items)))
    print("Rules in false-alarm reports:", dict(Counter(r for i in items if i["kind"] == "false_alarm" for r in i["rules"])))
    new_rows = []
    for item in todo:
        if "text_masked" not in item:
            item["status"] = "counted"
            continue
        print("\n" + "-" * 70)
        print(f"Report: {item['kind']}  |  system said: {item['verdict']} ({item['confidence']})")
        if item.get("needs_extra_scrutiny"):
            print("!! Extra scrutiny: user says a high-confidence scam verdict was wrong.")
        print(item["text_masked"])
        if item.get("comment_masked"):
            print("Comment:", item["comment_masked"])
        choice = input("True label? [s]cam / [l]egitimate / [r]eject / [k]skip: ").strip().lower()
        if choice in ("s", "l"):
            new_rows.append({"label": "scam" if choice == "s" else "safe", "category": f"feedback_{item['kind']}",
                             "text": item["text_masked"], "source": "user feedback, human reviewed",
                             "reviewed_on": date.today().isoformat()})
            item["status"] = "approved"
        elif choice == "r":
            item["status"] = "rejected"
    if new_rows:
        exists = REVIEWED.exists()
        with REVIEWED.open("a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(new_rows[0]))
            if not exists:
                w.writeheader()
            w.writerows(new_rows)
    pending.write_text("".join(json.dumps(i, ensure_ascii=False) + "\n" for i in items), encoding="utf-8")
    print(f"\nApproved {len(new_rows)} examples into {REVIEWED}. Retrain, then run the evaluation before deploying.")


if __name__ == "__main__":
    main()
