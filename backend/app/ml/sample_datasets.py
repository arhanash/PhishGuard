"""
Curated cybersecurity training datasets for PhishGuard.
Used for training the ML classification models (RandomForest and TF-IDF Naive Bayes/Logistic Regression).
"""

URL_DATASET = [
    # Legitimate (Label = 0)
    ("https://www.google.com", 0),
    ("https://github.com/torvalds/linux", 0),
    ("https://en.wikipedia.org/wiki/Phishing", 0),
    ("https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster", 0),
    ("https://www.microsoft.com/en-us/security", 0),
    ("https://aws.amazon.com/solutions/", 0),
    ("https://docs.python.org/3/library/urllib.parse.html", 0),
    ("https://www.apple.com/iphone-15-pro/", 0),
    ("https://netflix.com/browse", 0),
    ("https://www.linkedin.com/feed/", 0),
    ("https://www.cloudflare.com/learning/access-management/what-is-zero-trust/", 0),
    ("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3094", 0),
    ("https://www.harvard.edu/programs/computer-science/", 0),
    ("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers", 0),
    ("https://www.paypal.com/us/home", 0),
    ("https://chase.com/personal/banking", 0),
    ("https://www.nytimes.com/section/technology", 0),
    ("https://www.reddit.com/r/cybersecurity/", 0),
    ("https://pypi.org/project/scikit-learn/", 0),
    ("https://news.ycombinator.com/item?id=39865806", 0),
    ("https://support.google.com/mail/answer/8253", 0),
    ("https://www.cnn.com/world", 0),
    ("https://gitlab.com/explore/projects", 0),
    ("https://auth0.com/blog/what-is-oauth2/", 0),
    ("https://www.khanacademy.org/computing/computer-science", 0),

    # Phishing (Label = 1)
    ("http://192.168.1.100/paypal/login.php?cmd=_login-run", 1),
    ("http://paypa1-security-verification.xyz/account-update", 1),
    ("http://login.microsoftonline.com.account-verification-alert.top/signin", 1),
    ("http://secure-chase-banking-alert.buzz/verify/identity.php", 1),
    ("http://appleid.apple.com.verify-device-alert.tk/auth/login", 1),
    ("http://wellsfargo-secure-auth.club/online-banking/update-password", 1),
    ("http://218.92.0.12/webscr/login.html?security_token=90a8f8", 1),
    ("http://netflix-billing-issue-update.work/update-card.php", 1),
    ("http://binance-safety-check.click/account/login?ref=steal", 1),
    ("http://bankofamerica-customer-support.loan/identity-recovery/", 1),
    ("http://www.paypal.com-webscr.gq/cgi-bin/webscr?cmd=_login", 1),
    ("http://coinbase-wallet-verification.monster/restore-wallet", 1),
    ("http://office365-urgent-password-reset.icu/login.aspx?user=target", 1),
    ("http://secure-google-drive-shared-doc.cfd/view-document.html", 1),
    ("http://irs-tax-refund-claim-portal.date/direct-deposit", 1),
    ("http://amazon-prime-account-suspended.rest/billing-fix", 1),
    ("http://dhl-express-package-delivery-alert.men/track?parcel=99812", 1),
    ("http://user:pass@login-security-portal.com/authenticate", 1),
    ("http://metamask-extension-recovery.cyou/seed-phrase", 1),
    ("http://dropbox-shared-invoice-view.party/download.php?id=8831", 1),
    ("http://facebook-security-checkpoint.win/recover-account", 1),
    ("http://142.250.190.46/login.php", 1),
    ("http://xn--pypal-4ve.com/security/login", 1),
    ("http://bit.ly/3xFakeBankLoginPhish", 1),
    ("http://tinyurl.com/urgent-account-validation-notice", 1),
]

EMAIL_DATASET = [
    # Legitimate Emails (Label = 0)
    (
        "Sprint Planning Agenda for Thursday",
        "team-lead@techcorp.internal",
        "Hi Team,\n\nPlease find the sprint planning agenda attached for this Thursday at 10 AM. We will review Jira tickets for the upcoming release, discuss deployment blockers, and allocate story points.\n\nBest regards,\nAlex Mercer\nEngineering Lead",
        0
    ),
    (
        "Your GitHub weekly digest",
        "notifications@github.com",
        "Here's what happened across your subscribed repositories this week: 14 pull requests merged, 3 new issues opened in python-security-toolkit. Click to view repository summary on github.com.",
        0
    ),
    (
        "Monthly Electricity Bill - Account #908124",
        "billing@utilitypower.com",
        "Dear Customer,\n\nYour statement for the period of Oct 1 to Oct 31 is now ready. Total amount due: $78.45. Auto-pay is scheduled for Nov 25. You can view your usage breakdown by logging into your online account portal at utilitypower.com.",
        0
    ),
    (
        "Invitation: IEEE Cybersecurity Symposium 2026",
        "events@ieee-org.net",
        "Dear Researcher,\n\nYou are invited to submit papers for the upcoming 2026 IEEE International Symposium on Computer Security and Privacy. Topics include network intrusion detection, adversarial machine learning, and cryptography.",
        0
    ),
    (
        "Order Confirmation #409-1234981",
        "auto-confirm@amazon.com",
        "Hello Sarah,\n\nThanks for your order! We will notify you when your items ship. Expected delivery date is Friday, Nov 20. Track your package in the Amazon app or visit your orders page.",
        0
    ),
    (
        "Antigravity Dev Platform Release Notes v2.4",
        "updates@antigravity.dev",
        "We are pleased to announce the release of v2.4 featuring improved agent orchestration, faster workflow compilation, and upgraded dashboard analytics.",
        0
    ),
    (
        "Quarterly Financial Statement Ready for Review",
        "accounting@corporation.org",
        "Hello Department Managers,\n\nThe Q3 financial statements have been finalized and placed in the secure internal SharePoint directory. Please review your department expenditures before the Monday executive briefing.",
        0
    ),

    # Phishing Emails (Label = 1)
    (
        "URGENT: Your PayPal Account Has Been Suspended!",
        "service-security-alert@gmail.com",
        "Dear Valued Customer,\n\nWe detected unauthorized access to your PayPal account from an unknown IP address in Moscow, Russia. Your account has been temporarily LOCKED. You must verify your identity immediately within 24 hours or your balance will be permanently confiscated.\n\nClick the link below to verify your password and credit card number:\nhttp://paypa1-security-verification.xyz/account-update\n\nFailure to take immediate action will result in permanent account termination.\n\nPayPal Security Dept.",
        1
    ),
    (
        "Action Required: Office 365 Password Expiration Notice",
        "helpdesk-admin@temp-mail.org",
        "FINAL NOTICE: Your Microsoft 365 work password will expire in 1 hour!\n\nTo keep your current password and avoid losing email access, you must validate your credentials now at our portal:\nhttp://office365-urgent-password-reset.icu/login.aspx?user=target\n\nDo not ignore this warning.",
        1
    ),
    (
        "CONFIDENTIAL WIRE TRANSFER REQUEST",
        "ceo-office@company-exec-spoof.xyz",
        "Are you currently at your desk? I am in an urgent closed-door acquisition meeting and need an emergency wire transfer of $48,500 executed to an escrow account before 2:00 PM today. Do not call my phone as I cannot take calls right now. Send the bank confirmation directly to this email address.",
        1
    ),
    (
        "IRS Notice: Unclaimed Federal Tax Refund of $2,840.00",
        "irs-refunds@irs-portal-update.date",
        "Internal Revenue Service Notification:\n\nOur records show an overpayment on your recent tax return. A refund of $2,840.00 is awaiting your deposit. Submit your Social Security Number (SSN), date of birth, and direct deposit routing details here: http://irs-tax-refund-claim-portal.date/direct-deposit\n\nFunds will be forfeited if not claimed within 48 hours.",
        1
    ),
    (
        "Security Alert: Unauthorized Chase Wire Transfer Detected",
        "alerts@chase-fraud-preventions.buzz",
        "CHASE FRAUD ALERT: A wire transfer of $4,999.00 to crypto exchange Binance was attempted from your account. If you did not authorize this, verify your account details immediately: http://secure-chase-banking-alert.buzz/verify/identity.php or your funds will be lost.",
        1
    ),
    (
        "DHL: Undeliverable Parcel - Immediate Address Update Needed",
        "tracking-support@dhl-express-courier.men",
        "Your package with tracking number #DHL-981249 could not be delivered due to missing postal address fees ($1.99). Please open the attached document INVOICE_RECEIPT.iso and update your billing card information within 12 hours.",
        1
    ),
    (
        "Your Computer Has Been Compromised - Bitcoin Ransom Demand",
        "hacker-syndicate@onion-mail.club",
        "I have installed a remote access trojan on your system and recorded private webcam footage and passwords. Send $1,500 in Bitcoin to my BTC wallet within 48 hours or I will broadcast everything to all your social media and email contacts.",
        1
    ),
    (
        "HR Notice: Direct Deposit Payroll Information Verification",
        "hr-payroll@benefits-portal-login.cfd",
        "ATTENTION ALL EMPLOYEES:\n\nDue to our new banking system upgrade, all staff must log in and confirm their bank account number and routing number before Friday to ensure payroll is not delayed.\n\nLogin here: http://user:pass@login-security-portal.com/authenticate",
        1
    ),
]

