"""Run the two safe demo scenarios from the project brief:  python run_demo.py"""
from backend.services.risk_engine import analyze_email, format_report

PHISH = dict(
    sender="security-alert@account-check.invalid.test",
    subject="URGENT: Verify Your Account Immediately",
    body=("Dear Customer,\n\nWe detected unusual activity on your account. Your account will be suspended "
          "within 24 hours unless you verify your account immediately.\n\n"
          "Log in now to verify: http://198.51.100.10/verify-account\n\n"
          "Enter your password and confirm your login to restore access.\n\nSecurity Team"))
LEGIT = dict(
    sender="training@example.org",
    subject="Cybersecurity Workshop Reminder",
    body=("Hello team,\n\nThis is a reminder that the cybersecurity awareness workshop is on Friday at 3 PM "
          "in Room 204. The agenda is at https://example.org/workshops/cybersecurity.\n\n"
          "No action is needed unless you cannot attend; in that case just reply to this email.\n\nThanks,\nTraining Team"))

if __name__ == "__main__":
    for title, mail in (("SYNTHETIC PHISHING EXAMPLE", PHISH), ("LEGITIMATE EXAMPLE", LEGIT)):
        print("=" * 70, f"\n{title}\n" + "=" * 70)
        print(format_report(analyze_email(**mail)), "\n")
