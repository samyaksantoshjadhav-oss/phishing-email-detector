import pandas as pd
import random

# ---------------- LEGITIMATE DATA ----------------

legit_senders = [
    "hr@company.com",
    "careers@startup.in",
    "admin@college.edu",
    "accounts@bankofindia.in",
    "support@amazon.in",
    "placements@college.edu",
    "registrar@university.edu",
    "accounts@company.com",
    "it@office.com",
    "billing@electricityboard.in",
    "customer.service@airlines.com",
    "library@college.edu",
    "noreply@linkedin.com",
    "service@insurance.com"
]

legit_subjects = [
    "Interview Invitation",
    "Application Received Confirmation",
    "Exam Timetable Notification",
    "Order Delivery Confirmation",
    "Refund Processed Successfully",
    "Campus Recruitment Drive",
    "Admission Confirmation Letter",
    "Salary Credit Notification",
    "System Maintenance Notice",
    "Invoice Payment Received",
    "Flight Ticket Confirmation",
    "Library Due Reminder",
    "Policy Renewal Reminder",
    "Workshop Registration Confirmation"
]

legit_bodies = [
    "Dear Candidate, We are pleased to invite you for the next round of interview.",
    "Your recent order has been successfully delivered. Thank you for shopping with us.",
    "Your monthly bank account statement is available in the official portal.",
    "Please attend the scheduled meeting tomorrow at 2 PM in the conference hall.",
    "Your refund has been processed and will reflect in your account within 3 working days.",
    "The semester examination timetable has been uploaded to the official website.",
    "Your admission has been confirmed. Kindly complete the remaining formalities.",
    "Your salary for this month has been credited successfully.",
    "Scheduled maintenance will occur this Sunday from 1 AM to 4 AM.",
    "We have received your invoice payment. Thank you for your business.",
    "Your flight booking has been confirmed. Please carry valid ID proof.",
    "Please return the borrowed books before the due date.",
    "Your insurance policy is due for renewal next month.",
    "Your registration for the cybersecurity workshop is confirmed."
]

# ---------------- PHISHING DATA ----------------

phishing_senders = [
    "support@paypaI.com",
    "alert@secure-login.net",
    "security@bank-alerts.co",
    "lottery@win-big-now.com",
    "admin@verify-account.org",
    "ceo@company-secure.com",
    "notice@tax-refund-alert.com",
    "finance@urgent-transfer.com",
    "update@official-verification.com",
    "reward@claim-bonus-now.com"
]

phishing_subjects = [
    "Account Suspended",
    "Urgent Password Reset",
    "Verify Your Account Immediately",
    "You Won a Prize",
    "Security Alert",
    "Immediate Action Required",
    "Tax Refund Available",
    "Confidential Fund Transfer",
    "Update Banking Details",
    "Exclusive Bonus Reward"
]

phishing_bodies = [
    "Your account has been locked. Click here immediately to verify your identity.",
    "We detected unusual activity. Confirm your password now to avoid suspension.",
    "You have won a cash reward. Claim it before it expires.",
    "Your bank account will be permanently suspended if not verified.",
    "Failure to respond within 24 hours will result in account deletion.",
    "Transfer the requested funds immediately and confirm once completed.",
    "Submit your personal details now to receive your tax refund.",
    "Click the secure link below to restore account access.",
    "Provide your OTP to complete the verification process.",
    "Your credit card has been blocked. Reactivate immediately."
]

data = []

# Generate 100 legitimate emails
for _ in range(100):
    data.append([
        random.choice(legit_senders),
        random.choice(legit_subjects),
        random.choice(legit_bodies),
        0
    ])

# Generate 100 phishing emails
for _ in range(100):
    data.append([
        random.choice(phishing_senders),
        random.choice(phishing_subjects),
        random.choice(phishing_bodies),
        1
    ])

# Shuffle dataset
random.shuffle(data)

df = pd.DataFrame(data, columns=["sender_email", "subject", "body", "label"])

df.to_csv("data/emails.csv", index=False)

print("Dataset with 200 diverse emails generated successfully!")