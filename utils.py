import re

# ════════════════════════════════════════════════════════════════
#  utils.py — Phishing Email Detection System
#  Rule-based detection utilities
#  200+ suspicious keywords organised by attack category
# ════════════════════════════════════════════════════════════════


# ── SUSPICIOUS KEYWORDS (200+) ───────────────────────────────────
# Organised by attack category for maintainability

# 1. URGENCY & PRESSURE
URGENCY_KEYWORDS = [
    "urgent",
    "act now",
    "immediate action required",
    "respond immediately",
    "time sensitive",
    "limited time offer",
    "expires soon",
    "within 24 hours",
    "within 48 hours",
    "do not ignore",
    "final notice",
    "last warning",
    "action required",
    "last chance",
    "hurry",
    "don't delay",
    "respond urgently",
    "deadline today",
    "critically urgent",
    "time is running out",
]

# 2. ACCOUNT & SECURITY THREATS
ACCOUNT_KEYWORDS = [
    "verify your account",
    "verify your identity",
    "confirm your account",
    "confirm your identity",
    "update your account",
    "update your information",
    "update your password",
    "reset your password",
    "your password has expired",
    "unusual activity detected",
    "suspicious activity detected",
    "unauthorized access",
    "your account has been compromised",
    "security alert",
    "security breach",
    "we have detected a login",
    "login attempt from unknown device",
    "your account is at risk",
    "validate your account",
    "reactivate your account",
    "account suspended",
    "account disabled",
    "account will be closed",
    "account verification required",
    "your session has expired",
    "re-enter your credentials",
    "your account needs attention",
    "account locked",
    "temporary suspension",
    "unlock your account",
]

# 3. FINANCIAL SCAMS
FINANCIAL_KEYWORDS = [
    "you have won",
    "you are a winner",
    "claim your prize",
    "claim your reward",
    "lottery winner",
    "you have been selected",
    "congratulations you won",
    "prize money",
    "cash prize",
    "free gift",
    "gift card",
    "redeem your reward",
    "unclaimed funds",
    "wire transfer",
    "send money",
    "transfer funds",
    "bitcoin payment",
    "cryptocurrency payment",
    "bank account details",
    "routing number",
    "western union",
    "money gram",
    "inheritance funds",
    "million dollars",
    "billion dollars",
    "investment opportunity",
    "guaranteed returns",
    "risk free investment",
    "double your money",
    "winner",
    "lottery",
    "claim prize",
    "jackpot",
    "lucky draw",
    "sweepstakes",
]

# 4. CREDENTIAL HARVESTING
CREDENTIAL_KEYWORDS = [
    "enter your username",
    "enter your password",
    "provide your credentials",
    "submit your details",
    "fill in the form",
    "click here to login",
    "click here to verify",
    "click the link below",
    "click below to confirm",
    "sign in to continue",
    "log in to your account",
    "your credentials are required",
    "provide your personal information",
    "social security number",
    "date of birth",
    "credit card number",
    "card expiry",
    "cvv number",
    "bank details",
    "pin number",
    "mother maiden name",
    "ssn required",
    "confirm your pin",
    "enter card details",
    "provide billing information",
]

# 5. FAKE AUTHORITY / IMPERSONATION
AUTHORITY_KEYWORDS = [
    "dear customer",
    "dear valued customer",
    "dear account holder",
    "dear user",
    "this is an official notice",
    "official communication",
    "from the desk of",
    "irs notice",
    "tax refund",
    "government grant",
    "federal bureau",
    "microsoft support",
    "apple support",
    "google security",
    "paypal security",
    "amazon security alert",
    "your bank has flagged",
    "internal revenue service",
    "social security administration",
    "department of homeland security",
    "this email is from",
    "official notification",
    "your bank requires",
    "bank of america alert",
    "chase bank security",
    "paypal account alert",
]

# 6. MALWARE & ATTACHMENT TRICKS
MALWARE_KEYWORDS = [
    "open the attached file",
    "see attached document",
    "download the attachment",
    "view the attached invoice",
    "attached is your receipt",
    "open attachment to claim",
    "enable macros to view",
    "enable editing to view",
    "download and run",
    "install the update",
    "click to download",
    "your package is waiting",
    "delivery failed",
    "failed delivery attempt",
    "parcel could not be delivered",
    "track your shipment",
    "reschedule your delivery",
    "download required",
    "run this file",
    "open to proceed",
]

# 7. THREATENING LANGUAGE
THREAT_KEYWORDS = [
    "legal action will be taken",
    "we will take legal action",
    "lawsuit will be filed",
    "debt collection",
    "your debt is overdue",
    "payment overdue",
    "outstanding balance",
    "police report will be filed",
    "arrest warrant",
    "court summons",
    "criminal charges",
    "you owe",
    "immediate payment required",
    "pay now to avoid",
    "penalty charges",
    "your account will be reported",
    "collections agency",
    "face legal consequences",
    "final demand",
    "notice of default",
]

# 8. TECHNICAL TRICKS
TECHNICAL_KEYWORDS = [
    "your device has been infected",
    "virus detected",
    "malware detected",
    "your computer is at risk",
    "scan your device now",
    "your ip address has been flagged",
    "your ip has been blocked",
    "system error detected",
    "update required immediately",
    "your software is outdated",
    "click to remove virus",
    "call this number immediately",
    "tech support",
    "remote access",
    "we have accessed your computer",
    "your files have been encrypted",
    "ransomware detected",
    "hacker alert",
    "your data is at risk",
    "system compromised",
]

# ── COMBINED MASTER LIST ──────────────────────────────────────────
SUSPICIOUS_KEYWORDS = (
    URGENCY_KEYWORDS
    + ACCOUNT_KEYWORDS
    + FINANCIAL_KEYWORDS
    + CREDENTIAL_KEYWORDS
    + AUTHORITY_KEYWORDS
    + MALWARE_KEYWORDS
    + THREAT_KEYWORDS
    + TECHNICAL_KEYWORDS
)

# ── ATTACK TYPE CLASSIFICATION KEYWORDS ──────────────────────────
WHALING_KEYWORDS = [
    "ceo",
    "chief executive officer",
    "chief financial officer",
    "cfo",
    "board of directors",
    "executive team",
    "wire transfer request",
    "confidential transfer",
    "urgent wire",
    "approved by management",
    "executive approval",
    "c-suite",
]

SPEAR_PHISHING_KEYWORDS = [
    "as we discussed",
    "following up on our conversation",
    "as per your request",
    "as mentioned in the meeting",
    "your colleague",
    "your manager has requested",
    "your team lead",
    "internal request",
    "per our last call",
    "as agreed",
]

BANKING_KEYWORDS = [
    "bank account",
    "routing number",
    "wire transfer",
    "credit card",
    "debit card",
    "cvv",
    "pin number",
    "bank statement",
    "account balance",
    "transaction failed",
    "payment declined",
    "your card has been blocked",
    "billing information",
    "online banking",
    "net banking",
]


# ── SUSPICIOUS DOMAINS ───────────────────────────────────────────
# Organised by category — same structure as keywords

# 1. FAKE LOGIN / ACCOUNT VERIFICATION DOMAINS
SUSPICIOUS_DOMAINS_LOGIN = [
    "secure-login.net",
    "account-verify.net",
    "login-secure.org",
    "verify-account.co",
    "secure-update.net",
    "account-suspended.com",
    "login-alert.net",
    "reset-password-now.com",
    "signin-verification.net",
    "account-login-verify.com",
    "myaccount-secure.net",
    "login-confirm.net",
    "account-reactivate.com",
    "verify-signin.net",
    "update-your-login.com",
    "secure-signin.net",
    "account-locked-verify.com",
    "confirm-identity-now.net",
    "identity-verify-secure.com",
    "re-verify-account.net",
]

# 2. FAKE BANK / FINANCIAL DOMAINS
SUSPICIOUS_DOMAINS_BANK = [
    "bank-alerts.co",
    "bankofamerica-alert.com",
    "refund-processing.net",
    "wire-transfer-now.com",
    "bitcoin-transfer.com",
    "crypto-invest.net",
    "bank-update-required.com",
    "secure-banking-alert.net",
    "online-bank-verify.com",
    "paypal-secure.net",
    "paypal-account-alert.com",
    "paypal-verify-now.net",
    "banking-security-alert.net",
    "netbanking-update.com",
    "credit-card-verify.net",
    "card-block-alert.com",
    "transaction-failed-alert.net",
    "bank-account-suspended.com",
    "iban-verify.net",
    "swift-transfer-secure.com",
]

# 3. FAKE TECH SUPPORT / IMPERSONATION DOMAINS
SUSPICIOUS_DOMAINS_TECH = [
    "microsoft-alert.net",
    "apple-id-verify.com",
    "amazon-security.org",
    "google-verify.net",
    "customer-support-alert.com",
    "microsoft-security-team.net",
    "apple-support-verify.com",
    "google-account-alert.net",
    "amazon-order-alert.com",
    "netflix-account-verify.net",
    "support-helpdesk-alert.com",
    "tech-support-now.net",
    "windows-security-alert.com",
    "icloud-verify-now.net",
    "gmail-account-alert.com",
    "facebook-security-alert.net",
    "instagram-verify-now.com",
    "whatsapp-account-suspend.net",
    "adobe-license-alert.com",
    "zoom-account-verify.net",
]

# 4. FAKE PRIZE / LOTTERY DOMAINS
SUSPICIOUS_DOMAINS_PRIZE = [
    "win-big-now.com",
    "prize-winner.net",
    "claim-reward.org",
    "free-gift-claim.com",
    "lottery-winner-claim.com",
    "jackpot-winner-2024.net",
    "congratulations-winner.com",
    "you-have-won-prize.net",
    "free-iphone-claim.com",
    "lucky-draw-winner.net",
    "cash-prize-claim.org",
    "sweepstakes-winner.com",
    "reward-points-claim.net",
    "bonus-cash-winner.com",
    "gift-card-free-claim.net",
    "million-dollar-winner.com",
    "prize-collect-now.net",
    "winning-notification.com",
    "exclusive-reward-claim.net",
    "special-offer-winner.com",
]

# 5. FAKE DELIVERY / SHIPPING DOMAINS
SUSPICIOUS_DOMAINS_DELIVERY = [
    "urgent-delivery.net",
    "package-tracking.co",
    "failed-delivery-alert.com",
    "parcel-on-hold.net",
    "delivery-reSchedule.com",
    "dhl-alert-delivery.net",
    "fedex-package-alert.com",
    "ups-delivery-failed.net",
    "courier-delivery-alert.com",
    "shipment-pending-confirm.net",
    "track-your-parcel-now.com",
    "post-office-redelivery.net",
    "customs-clearance-fee.com",
    "package-held-customs.net",
    "express-delivery-notify.com",
]

# 6. FAKE GOVERNMENT / TAX DOMAINS
SUSPICIOUS_DOMAINS_GOVT = [
    "irs-refund.net",
    "tax-refund-claim.com",
    "update-info.net",
    "govt-grant-apply.com",
    "irs-tax-refund-2024.net",
    "tax-return-pending.com",
    "income-tax-refund-alert.net",
    "government-relief-fund.com",
    "covid-relief-grant.net",
    "stimulus-check-claim.com",
    "social-security-alert.net",
    "dmv-license-renewal.com",
    "passport-renewal-alert.net",
    "visa-application-pending.com",
    "immigration-alert-now.net",
]

# ── COMBINED SUSPICIOUS DOMAINS MASTER LIST ──────────────────────
SUSPICIOUS_DOMAINS = (
    SUSPICIOUS_DOMAINS_LOGIN
    + SUSPICIOUS_DOMAINS_BANK
    + SUSPICIOUS_DOMAINS_TECH
    + SUSPICIOUS_DOMAINS_PRIZE
    + SUSPICIOUS_DOMAINS_DELIVERY
    + SUSPICIOUS_DOMAINS_GOVT
)


# ── TRUSTED DOMAINS WHITELIST ────────────────────────────────────
# Links from these domains are SAFE and will NOT be flagged
# Organised by category — same structure as keywords

# 1. SEARCH ENGINES
TRUSTED_SEARCH = [
    "google.com", "google.co.in", "google.co.uk", "google.com.au",
    "bing.com", "yahoo.com", "yahoo.co.in",
    "duckduckgo.com", "baidu.com", "ask.com",
]

# 2. MAJOR TECH COMPANIES
TRUSTED_TECH = [
    "microsoft.com", "outlook.com", "office.com", "live.com",
    "office365.com", "azure.com", "onedrive.com", "sharepoint.com",
    "apple.com", "icloud.com", "itunes.com",
    "amazon.com", "aws.amazon.com", "amazon.in",
    "adobe.com", "acrobat.adobe.com",
    "oracle.com", "ibm.com", "intel.com",
    "cisco.com", "vmware.com", "salesforce.com",
    "dropbox.com", "box.com",
]

# 3. EMAIL & COMMUNICATION
TRUSTED_EMAIL = [
    "gmail.com", "mail.google.com",
    "yahoo.com", "yahoo.co.in", "ymail.com",
    "outlook.com", "hotmail.com", "live.com",
    "protonmail.com", "proton.me",
    "zoho.com", "zohomail.com",
    "icloud.com",
    "rediffmail.com",
]

# 4. VIDEO & MEDIA
TRUSTED_MEDIA = [
    "youtube.com", "youtu.be",
    "netflix.com", "hotstar.com", "disneyplus.com",
    "primevideo.com", "hulu.com",
    "spotify.com", "soundcloud.com",
    "twitch.tv", "vimeo.com",
    "dailymotion.com",
]

# 5. SOCIAL MEDIA
TRUSTED_SOCIAL = [
    "facebook.com", "fb.com",
    "instagram.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "whatsapp.com", "web.whatsapp.com",
    "telegram.org", "t.me",
    "reddit.com",
    "pinterest.com", "snapchat.com",
    "tiktok.com", "discord.com",
    "quora.com",
]

# 6. DEVELOPER & TECH COMMUNITY
TRUSTED_DEV = [
    "github.com", "github.io",
    "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "stackexchange.com",
    "npmjs.com", "pypi.org",
    "replit.com", "codepen.io",
    "heroku.com", "netlify.com", "vercel.com",
    "digitalocean.com", "linode.com",
    "docker.com", "kubernetes.io",
]

# 7. EDUCATION
TRUSTED_EDUCATION = [
    "coursera.org", "udemy.com", "edx.org",
    "khanacademy.org", "skillshare.com",
    "pluralsight.com", "linkedin.com/learning",
    "w3schools.com", "geeksforgeeks.org",
    "tutorialspoint.com", "javatpoint.com",
    "mit.edu", "stanford.edu", "harvard.edu",
    "nptel.ac.in", "swayam.gov.in",
]

# 8. NEWS & INFORMATION
TRUSTED_NEWS = [
    "wikipedia.org", "wikimedia.org",
    "bbc.com", "bbc.co.uk",
    "cnn.com", "reuters.com", "apnews.com",
    "theguardian.com", "nytimes.com",
    "ndtv.com", "timesofindia.com",
    "hindustantimes.com", "thehindu.com",
    "indianexpress.com", "livemint.com",
    "economictimes.com", "businessstandard.com",
]

# 9. INDIAN GOVERNMENT & BANKING
TRUSTED_INDIA = [
    "gov.in", "nic.in", "india.gov.in",
    "mygov.in", "digilocker.gov.in",
    "uidai.gov.in", "incometax.gov.in",
    "irctc.co.in", "indianrailways.gov.in",
    "swayam.gov.in", "nptel.ac.in",
    "sbi.co.in", "onlinesbi.com",
    "hdfcbank.com", "icicibank.com",
    "axisbank.com", "kotak.com",
    "pnbindia.in", "bankofbaroda.in",
    "upi.gov.in", "npci.org.in",
]

# 10. PAYMENT & SHOPPING
TRUSTED_PAYMENT = [
    "paypal.com", "paypal.me",
    "razorpay.com", "paytm.com",
    "phonepe.com", "gpay.app",
    "stripe.com", "square.com",
    "visa.com", "mastercard.com",
    "flipkart.com", "myntra.com",
    "snapdeal.com", "meesho.com",
    "nykaa.com", "ajio.com",
    "shopify.com", "etsy.com",
    "ebay.com", "aliexpress.com",
]

# 11. CLOUD & PRODUCTIVITY
TRUSTED_CLOUD = [
    "drive.google.com", "docs.google.com",
    "sheets.google.com", "slides.google.com",
    "calendar.google.com", "meet.google.com",
    "zoom.us", "teams.microsoft.com",
    "slack.com", "notion.so",
    "trello.com", "asana.com",
    "jira.atlassian.com", "confluence.atlassian.com",
    "figma.com", "canva.com",
    "miro.com", "airtable.com",
]

# 12. SECURITY & ANTIVIRUS (these sites are obviously safe)
TRUSTED_SECURITY = [
    "kaspersky.com", "norton.com",
    "mcafee.com", "bitdefender.com",
    "malwarebytes.com", "avast.com",
    "avg.com", "eset.com",
    "virustotal.com", "shodan.io",
    "haveibeenpwned.com",
    "owasp.org", "sans.org",
    "nist.gov", "cve.mitre.org",
]

# ── COMBINED TRUSTED DOMAINS MASTER LIST ─────────────────────────
TRUSTED_DOMAINS = (
    TRUSTED_SEARCH
    + TRUSTED_TECH
    + TRUSTED_EMAIL
    + TRUSTED_MEDIA
    + TRUSTED_SOCIAL
    + TRUSTED_DEV
    + TRUSTED_EDUCATION
    + TRUSTED_NEWS
    + TRUSTED_INDIA
    + TRUSTED_PAYMENT
    + TRUSTED_CLOUD
    + TRUSTED_SECURITY
)


def check_suspicious_links(text: str) -> bool:
    """
    Check if the email text contains suspicious links.
    Trusted domains (Google, Microsoft, Apple etc.) are whitelisted.
    Returns True only if a non-trusted HTTP/HTTPS link is found.
    """
    # Find all URLs in the text
    urls = re.findall(r'https?://\S+', text.lower())

    if not urls:
        return False  # no links at all — not suspicious

    for url in urls:
        # Check if URL belongs to a trusted domain
        is_trusted = any(trusted in url for trusted in TRUSTED_DOMAINS)
        if not is_trusted:
            return True  # found a non-trusted link — suspicious

    return False  # all links were from trusted domains


def classify_attack_type(text: str, keyword_flag: bool) -> str:
    """
    Classify the type of phishing attack based on email content.
    Returns a string describing the attack type.
    """
    text_lower = text.lower()

    # Check for whaling (CEO/executive fraud)
    if any(k in text_lower for k in WHALING_KEYWORDS):
        return "Whaling Attack"

    # Check for lottery / prize scam
    if any(k in text_lower for k in ["lottery", "winner", "jackpot", "prize", "sweepstakes"]):
        return "Prize / Lottery Scam"

    # Check for banking phishing
    if any(k in text_lower for k in BANKING_KEYWORDS):
        return "Banking / Credential Phishing"

    # Check for spear phishing
    if any(k in text_lower for k in SPEAR_PHISHING_KEYWORDS):
        return "Spear Phishing Attack"

    # Generic mass phishing
    if keyword_flag:
        return "Mass Email Phishing"

    return "General Email Phishing"


def get_matched_keywords(text: str) -> list:
    """
    Return a list of all suspicious keywords found in the text.
    Useful for detailed reporting.
    """
    text_lower = text.lower()
    matched = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            matched.append(keyword)
    return matched


def calculate_threat_score(phishing_prob: float,
                            domain_flag: bool,
                            keyword_flag: bool,
                            link_flag: bool) -> float:
    """
    Calculate the composite threat score.
    Base score = ML model phishing probability (0-100)
    Bonuses:
      +10 if suspicious domain detected
      +5  if phishing keywords found
      +5  if suspicious links present
    Max score capped at 100.
    """
    score = phishing_prob
    if domain_flag:  score += 10
    if keyword_flag: score += 5
    if link_flag:    score += 5
    return min(score, 100.0)


def classify_risk_level(threat_score: float) -> str:
    """
    Classify risk level based on threat score.
      >= 70 → HIGH
      >= 55 → MEDIUM
      < 55  → LOW
    """
    if threat_score >= 70:
        return "HIGH"
    elif threat_score >= 55:
        return "MEDIUM"
    else:
        return "LOW"


def get_confidence_label(phishing_prob: float) -> tuple:
    """
    Returns (confidence_label, confidence_index) based on
    how far the probability is from 50% (uncertain midpoint).
    """
    conf_index = abs(phishing_prob - 50)
    if conf_index >= 25:
        label = "HIGH"
    elif conf_index >= 10:
        label = "MODERATE"
    else:
        label = "LOW"
    return label, round(conf_index, 2)# ════════════════════════════════════════════════════════════════
#  DETECTION FUNCTIONS
# ════════════════════════════════════════════════════════════════

def check_suspicious_keywords(text: str) -> bool:
    """
    Check if the email text contains any suspicious phishing keywords.
    Returns True if any suspicious keyword is found.
    """
    text_lower = text.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            return True
    return False


def check_suspicious_domain(email: str) -> bool:
    """
    Check if the sender email contains a known suspicious domain.
    Returns True if a suspicious domain is found.
    """
    email_lower = email.lower()
    for domain in SUSPICIOUS_DOMAINS:
        if domain in email_lower:
            return True
    return False