"""Generate the SYNTHETIC email dataset (safe, fictional, reproducible).

Run from the project root:   python data/generate_dataset.py

Safety rules enforced here:
  * only reserved/fictional domains: example.com/.org/.net, *.invalid.test, *.example
  * IPs only from documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
  * no real brands, no real URLs, nothing is ever sent or visited
The dataset intentionally includes HARD cases (urgent-sounding legitimate emails and
polite, well-written phishing) so that rule-based and ML results are realistic.
"""
import argparse
import csv
import os
import random
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.utils.preprocessing import extract_sender_domain  # noqa: E402

FIRST = ["Aarav", "Priya", "Sam", "Maya", "Liam", "Zoya", "Noah", "Isha", "Ravi", "Emma", "Kabir", "Sara"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
TOPICS = ["password managers", "safe browsing", "cloud basics", "data privacy", "open-source tools", "AI in education"]
DOC_IPS = ["198.51.100", "203.0.113", "192.0.2"]


def ip(r): return f"{r.choice(DOC_IPS)}.{r.randint(2, 250)}"
def num(r): return r.randint(10000, 99999)
def rec(sender, subject, body, urls="", att="", category=""):
    return dict(sender=sender, subject=subject, body=body, urls=urls, attachment_name=att, category=category)

# ------------------------------ LEGITIMATE ------------------------------
def university_notice(r):
    u = "https://example.org/registrar/courses"
    m = r.choice(MONTHS)
    return rec("registrar@example.org", f"Semester registration opens {m} {r.randint(1, 28)}",
               f"Hello students,\n\nRegistration for the next semester opens on {m} {r.randint(1, 28)}. Course details are at {u}. "
               f"Contact the registrar's office if you have questions.\n\nRegards,\nRegistrar's Office", u, "", "university_notice")

def hr_update(r):
    u = "https://hr.example.com/policies"
    if r.random() < 0.35:  # HARD legitimate: urgent wording, real business context
        return rec("hr@example.com", "Urgent: Submit your documents today",
                   f"Hi {r.choice(FIRST)},\n\nPlease submit your signed onboarding documents today so payroll can be processed on time. "
                   f"Upload them at https://hr.example.com/documents.\n\nHR Team", "https://hr.example.com/documents", "", "hr_update_urgent")
    return rec("hr@example.com", f"Updated leave policy for {r.randint(2025, 2027)}",
               f"Hi all,\n\nThe leave policy has been updated. You can read the details at {u}. No action is required.\n\nHR Team",
               u, "", "hr_update")

def project_update(r):
    u = "https://projects.example.com/board"
    return rec(f"{r.choice(FIRST).lower()}@example.com", f"Sprint {r.randint(1, 20)} status update",
               f"Hi team,\n\nWe finished {r.randint(3, 12)} tasks this sprint and {r.randint(1, 4)} carry over. Board: {u}.\n\nThanks!",
               u, r.choice(["", "sprint_report.pdf", "burndown.xlsx"]), "project_update")

def meeting_reminder(r):
    u = f"https://meet.example.net/room-{r.randint(1, 60)}"
    return rec("calendar@example.net", f"Reminder: project sync on {r.choice(DAYS)} at {r.randint(1, 5)} PM",
               f"Hello,\n\nThis is a reminder about the project sync. Join here: {u}\n\nAgenda attached.", u, r.choice(["", "agenda.pdf", "agenda.docx"]), "meeting_reminder")

def shopping_confirmation(r):
    n = num(r); u = f"https://exampleshop.example.com/orders/{n}"
    return rec("orders@exampleshop.example.com", f"Your order #{n} has shipped",
               f"Hi {r.choice(FIRST)},\n\nThanks for your order. It shipped today and should arrive in {r.randint(2, 6)} days. Track it at {u}.",
               u, r.choice(["", f"receipt_{n}.pdf"]), "shopping_confirmation")

def newsletter(r):
    u = "https://news.example.net/latest"
    return rec("news@example.net", f"This month in tech: {r.choice(TOPICS)}",
               f"Hello readers,\n\nThis month we cover {r.choice(TOPICS)} and {r.choice(TOPICS)}. Read the full issue at {u}. Unsubscribe any time from your profile.",
               u, "", "newsletter")

def password_change(r):
    return rec("no-reply@example.com", "Your password was changed",
               f"Hi {r.choice(FIRST)},\n\nThe password for your account was changed on {r.choice(MONTHS)} {r.randint(1, 28)}. If this was you, no action is needed. "
               f"If it was not you, contact the helpdesk through https://example.com/help.", "https://example.com/help", "", "password_change_confirmation")

def bank_notification(r):
    u = "https://examplebank.example.com/statements"
    return rec("ExampleBank Alerts <alerts@examplebank.example.com>", f"Your {r.choice(MONTHS)} statement is ready",
               f"Hello {r.choice(FIRST)},\n\nYour monthly statement is available in the ExampleBank app or at {u}. "
               f"We will never ask for your password by email.", u, "", "bank_notification")

LEGIT = [university_notice, hr_update, project_update, meeting_reminder, shopping_confirmation, newsletter, password_change, bank_notification]

# ------------------------------- PHISHING -------------------------------
def fake_account_verification(r):
    sender = r.choice(["security-alert@account-check.invalid.test", "support@examplebank-secure.example.net",
                       "ExampleBank Support <alerts@verify-mail.invalid.test>", "no-reply@verify-examplebank.example.org"])
    u = r.choice([f"http://{ip(r)}/verify-account", "http://examplebank.verify-login.example.net/signin", f"http://secure-login.invalid.test/account/verify?id={num(r)}"])
    return rec(sender, r.choice(["URGENT: Verify Your Account Immediately", "Account suspended - action required", "Security alert: confirm your identity"]),
               f"Dear Customer,\n\nUnusual activity was detected. Your account will be suspended within 24 hours unless you verify your account immediately: {u}\n"
               f"Enter your password to restore access.", u, "", "fake_account_verification")

def fake_invoice(r):
    n = num(r)
    return rec("billing@invoice-center.example.net", f"Invoice #{n} overdue - payment failed",
               f"Dear Sir/Madam,\n\nYour invoice is past due and payment failed. Open the attached invoice and settle the outstanding balance today.",
               "", r.choice([f"Invoice_{n}.pdf.exe", f"Invoice_{n}.zip", f"invoice_{n}.html", f"payment_{n}.js"]), "fake_invoice")

def fake_prize(r):
    u = f"http://claim-prize.example.net/{num(r)}"
    return rec("rewards@prize-center.invalid.test", "Congratulations! You have won a free gift!!!",
               f"Dear Winner,\n\nYou have won! Claim your prize now: {u}\nConfirm your personal details and card number to receive it.", u, "", "fake_prize")

def fake_password_expiration(r):
    u = r.choice([f"http://{ip(r)}/reset", "http://it-portal.update-login.example.net/password"])
    return rec("it-helpdesk@example-support.invalid.test", "Your password expires today",
               f"Dear User,\n\nYour password expires today. Update your password immediately to keep access: {u}", u, "", "fake_password_expiration")

def fake_delivery(r):
    u = f"http://short.example/{r.choice(['aB3xY', 'k9Lm2', 'Zq7Rt'])}{r.randint(0, 9)}"
    return rec("delivery@parcel-track.example.net", "Delivery failed - reschedule now",
               f"Hello Customer,\n\nWe could not deliver your parcel. Confirm your address and pay the small fee within 24 hours: {u}", u, "", "fake_delivery")

def fake_hr_request(r):
    return rec("hr-payroll@example-hr.example.net", "Action required: confirm your payroll details",
               "Dear Employee,\n\nTo avoid delays in your salary, please confirm your payroll details and send your bank account number by reply. Immediate action is required.",
               "", "", "fake_hr_request")

def fake_executive_request(r):
    return rec("ceo.office@example-corp.invalid.test", "Quick task - confidential",
               "Are you at your desk? I am in a meeting and need you to buy gift cards for a client. Do this immediately and reply with the codes. Keep it confidential.",
               "", "", "fake_executive_request")

def subtle_document_share(r):  # HARD phishing: calm wording, no urgency
    u = f"https://docs-share.example.net/view/{num(r)}"
    return rec("docs-share@example-docs.example.net", "Document shared with you",
               f"Hi {r.choice(FIRST)},\n\nA colleague shared the meeting notes with you. You can view them here: {u}", u, "", "subtle_document_share")

def subtle_attachment(r):  # HARD phishing: polite, risky attachment only
    return rec("projects@example-team.example.net", "Updated project files",
               "Hello,\n\nPlease see the updated project files attached and let me know your thoughts.", "", r.choice(["files.zip", "notes.html"]), "subtle_attachment")

PHISH = [fake_account_verification, fake_invoice, fake_prize, fake_password_expiration, fake_delivery,
         fake_hr_request, fake_executive_request, subtle_document_share, subtle_attachment]


def generate(n: int, seed: int):
    r = random.Random(seed)
    rows = []
    for i in range(1, n + 1):
        is_phish = r.random() < 0.45
        row = r.choice(PHISH if is_phish else LEGIT)(r)
        row.update(email_id=f"EML-{i:05d}", label="PHISHING" if is_phish else "LEGITIMATE",
                   sender_domain=extract_sender_domain(row["sender"]))
        rows.append(row)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=600)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing_email_dataset.csv"))
    a = ap.parse_args()
    rows = generate(a.n, a.seed)
    cols = ["email_id", "sender", "sender_domain", "subject", "body", "urls", "attachment_name", "label", "category"]
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows({c: row[c] for c in cols} for row in rows)
    print(f"Saved {len(rows)} rows to {a.out}")
    print("Label counts:", dict(Counter(x["label"] for x in rows)))
    print("Categories:", dict(sorted(Counter(x["category"] for x in rows).items())))


if __name__ == "__main__":
    main()
