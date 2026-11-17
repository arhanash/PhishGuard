import re
import math
from urllib.parse import urlparse

# Commonly abused or high-risk TLDs according to Spamhaus / APWG reports
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "club",
    "work", "loan", "men", "date", "racing", "win", "party", "space", "online",
    "vip", "rest", "cam", "fit", "icu", "cyou", "monster", "cfd"
}

# Known URL shorteners often used in phishing to mask destination
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "goo.gl",
    "cutt.ly", "rebrand.ly", "v.gd", "soo.gd", "tiny.cc", "s.id", "rotf.lol",
    "rb.gy", "shorturl.at"
}

# Sensitive tokens commonly exploited in phishing URLs
TARGET_KEYWORDS = [
    "login", "signin", "verify", "account", "secure", "update", "banking",
    "paypal", "security", "admin", "billing", "password", "confirm", "wallet",
    "recover", "auth", "validation", "support", "office365", "netflix",
    "appleid", "wellsfargo", "chase", "metaverse", "binance", "coinbase"
]

# Urgency and coercive phrases common in phishing emails
URGENT_PHRASES = [
    "urgent", "immediately", "account suspended", "suspended within", "action required",
    "unauthorized access", "security breach", "terminated", "final notice",
    "24 hours", "48 hours", "will be closed", "unusual activity", "locked out",
    "confirm identity", "verify your identity", "reset required", "expire soon",
    "law enforcement", "arrest warrant", "subpoena", "fraudulent activity"
]

CREDENTIAL_PHRASES = [
    "enter your password", "confirm password", "verify login", "security questions",
    "two-factor authentication code", "ssn", "social security", "pin code",
    "secret recovery phrase", "seed phrase", "private key", "credit card details",
    "cvv", "atm pin", "update billing"
]

FINANCIAL_SCAM_PHRASES = [
    "wire transfer", "unpaid invoice", "bitcoin", "btc wallet", "gift card",
    "lottery winner", "inheritance", "western union", "overdue payment",
    "payroll update", "direct deposit change", "bonus payout", "reimbursement claim"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".scr", ".vbs", ".bat", ".cmd", ".iso", ".img", ".ps1", ".jar",
    ".wsf", ".hta", ".pif", ".xlsm", ".docm"
]

def calculate_entropy(text: str) -> float:
    """Calculate Shannon Entropy of a string to detect random DGAs or hex hashes."""
    if not text:
        return 0.0
    prob_dist = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = -sum([p * math.log(p, 2) for p in prob_dist])
    return entropy

def is_ip_address(domain: str) -> bool:
    """Check if domain is a raw IPv4 or IPv6 address."""
    # IPv4 regex
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    # Hex or Octal IP pattern e.g. 0x7f000001
    hex_ip = r"^0x[0-9a-fA-F]+$"
    clean_domain = domain.split(":")[0].strip("[]")
    if re.match(ipv4_pattern, clean_domain) or re.match(hex_ip, clean_domain):
        return True
    return False

def extract_url_features(url: str) -> dict:
    """
    Extracts lexical, structural, and semantic features from a URL.
    Returns both numerical feature vector dict for ML and detailed explainability indicators.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        # Prepend http:// for parsing if absent
        parse_target = "http://" + url
    else:
        parse_target = url

    try:
        parsed = urlparse(parse_target)
    except Exception:
        parsed = urlparse("http://invalid.target")

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query

    # Remove port from netloc for domain analysis
    hostname = netloc.split(":")[0]

    # Subdomain analysis
    domain_parts = [p for p in hostname.split(".") if p]
    subdomain_depth = max(0, len(domain_parts) - 2) if len(domain_parts) > 2 else 0
    tld = domain_parts[-1] if domain_parts else ""

    # Check for homoglyph / punycode
    has_punycode = 1 if "xn--" in hostname else 0

    # Check for IP in domain
    has_ip = 1 if is_ip_address(hostname) else 0

    # Shortener check
    is_shortener = 1 if any(hostname.endswith(s) for s in SHORTENER_DOMAINS) else 0

    # Suspicious TLD check
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Entropy
    hostname_entropy = calculate_entropy(hostname)
    path_entropy = calculate_entropy(path)

    # Keyword matching
    target_kw_matches = [kw for kw in TARGET_KEYWORDS if kw in url.lower()]
    kw_count = len(target_kw_matches)

    # Basic counts
    url_len = len(url)
    domain_len = len(hostname)
    path_len = len(path)
    dot_count = url.count(".")
    hyphen_count = url.count("-")
    at_count = url.count("@")
    slash_count = url.count("/")
    question_count = url.count("?")
    equal_count = url.count("=")
    percent_count = url.count("%")
    digit_count = sum(c.isdigit() for c in url)
    digit_ratio = (digit_count / url_len) if url_len > 0 else 0.0

    has_port = 1 if ":" in netloc and not is_ip_address(hostname) else 0
    is_https = 1 if scheme == "https" else 0

    features = {
        "url_len": url_len,
        "domain_len": domain_len,
        "path_len": path_len,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "at_count": at_count,
        "slash_count": slash_count,
        "question_count": question_count,
        "equal_count": equal_count,
        "percent_count": percent_count,
        "digit_count": digit_count,
        "digit_ratio": digit_ratio,
        "has_ip": has_ip,
        "is_shortener": is_shortener,
        "has_punycode": has_punycode,
        "subdomain_depth": subdomain_depth,
        "hostname_entropy": hostname_entropy,
        "path_entropy": path_entropy,
        "is_suspicious_tld": is_suspicious_tld,
        "kw_count": kw_count,
        "has_port": has_port,
        "is_https": is_https,
    }

    metadata = {
        "hostname": hostname,
        "tld": tld,
        "scheme": scheme,
        "matched_keywords": target_kw_matches,
        "subdomain_depth": subdomain_depth,
        "hostname_entropy": round(hostname_entropy, 3),
        "is_ip": bool(has_ip),
        "is_shortener": bool(is_shortener),
        "has_punycode": bool(has_punycode),
        "suspicious_tld": bool(is_suspicious_tld),
        "has_at_symbol": bool(at_count > 0),
    }

    return features, metadata

def extract_email_features(raw_content: str, subject: str = "", sender: str = "") -> dict:
    """
    Extracts text, header, and behavioral cues from email contents.
    """
    combined_text = f"{subject}\n{sender}\n{raw_content}".lower()
    subject_lower = subject.lower() if subject else ""
    sender_lower = sender.lower() if sender else ""

    # Parse headers if raw_content appears to be RFC 822 or MIME
    if not sender and "from:" in raw_content.lower():
        from_match = re.search(r"from:\s*([^\r\n]+)", raw_content, re.IGNORECASE)
        if from_match:
            sender_lower = from_match.group(1).lower()

    if not subject and "subject:" in raw_content.lower():
        subj_match = re.search(r"subject:\s*([^\r\n]+)", raw_content, re.IGNORECASE)
        if subj_match:
            subject_lower = subj_match.group(1).lower()

    # Search for URLs in the email body
    url_pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+"
    found_urls = re.findall(url_pattern, raw_content)

    # Urgency analysis
    matched_urgency = [p for p in URGENT_PHRASES if p in combined_text]
    urgency_score = len(matched_urgency)

    # Credential theft indicators
    matched_creds = [p for p in CREDENTIAL_PHRASES if p in combined_text]
    cred_score = len(matched_creds)

    # Financial / extortion phrases
    matched_financial = [p for p in FINANCIAL_SCAM_PHRASES if p in combined_text]
    financial_score = len(matched_financial)

    # Dangerous attachment extensions
    matched_extensions = [ext for ext in SUSPICIOUS_EXTENSIONS if ext in combined_text]

    # Capitalization & exclamation analysis
    total_alpha = sum(c.isalpha() for c in raw_content)
    upper_alpha = sum(c.isupper() for c in raw_content)
    caps_ratio = (upper_alpha / total_alpha) if total_alpha > 0 else 0.0
    exclamation_count = raw_content.count("!")

    # Sender impersonation check:
    # Does sender display name contain trusted brand (e.g. PayPal, Apple, Microsoft, Chase)
    # but actual email address is generic or spoofed?
    brand_keywords = ["paypal", "microsoft", "apple", "google", "amazon", "netflix", "bank", "wells fargo", "chase", "irs", "gov"]
    impersonation_flag = False
    impersonated_brand = None
    free_providers = ["@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com", "@aol.com", "@mail.ru", "@protonmail.com"]

    for brand in brand_keywords:
        if brand in sender_lower:
            # Check if domain actually matches brand
            brand_domain_slug = brand.replace(" ", "")
            if any(free in sender_lower for free in free_providers) or brand_domain_slug not in sender_lower.split("@")[-1]:
                impersonation_flag = True
                impersonated_brand = brand
                break

    features = {
        "urgency_count": urgency_score,
        "cred_count": cred_score,
        "financial_count": financial_score,
        "suspicious_ext_count": len(matched_extensions),
        "embedded_urls_count": len(found_urls),
        "caps_ratio": caps_ratio,
        "exclamation_count": exclamation_count,
        "is_impersonation": 1 if impersonation_flag else 0,
        "text_length": len(raw_content),
    }

    metadata = {
        "subject": subject_lower,
        "sender": sender_lower,
        "found_urls": found_urls[:10],
        "matched_urgency": matched_urgency,
        "matched_credentials": matched_creds,
        "matched_financial": matched_financial,
        "matched_extensions": matched_extensions,
        "caps_ratio": round(caps_ratio, 3),
        "exclamation_count": exclamation_count,
        "impersonation_flag": impersonation_flag,
        "impersonated_brand": impersonated_brand,
    }

    return features, metadata, combined_text

