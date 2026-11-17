export const SAMPLE_CASES = {
  urls: [
    {
      id: 'url-safe-google',
      label: 'Google Search (Safe)',
      category: 'Safe',
      url: 'https://www.google.com',
      badgeColor: 'border-emerald-500/40 text-emerald-400 bg-emerald-950/30',
      description: 'Standard legitimate search engine portal with HTTPS and established domain reputation.'
    },
    {
      id: 'url-safe-github',
      label: 'GitHub Linux Kernel (Safe)',
      category: 'Safe',
      url: 'https://github.com/torvalds/linux',
      badgeColor: 'border-emerald-500/40 text-emerald-400 bg-emerald-950/30',
      description: 'Verified public open-source repository hosted on github.com.'
    },
    {
      id: 'url-susp-short',
      label: 'Bit.ly Shortened Link (Suspicious)',
      category: 'Suspicious',
      url: 'http://bit.ly/3xFakeBankLoginPhish',
      badgeColor: 'border-amber-500/40 text-amber-400 bg-amber-950/30',
      description: 'URL shortener masking true destination domain over unencrypted HTTP.'
    },
    {
      id: 'url-mal-typo',
      label: 'PayPal Typosquatting .xyz (Malicious)',
      category: 'Malicious',
      url: 'http://paypa1-security-verification.xyz/account-update',
      badgeColor: 'border-rose-500/40 text-rose-400 bg-rose-950/30',
      description: 'Typosquatting attack replacing letter "l" with digit "1" on an abused .xyz TLD.'
    },
    {
      id: 'url-mal-ip',
      label: 'Direct IP Credential Harvester (Malicious)',
      category: 'Malicious',
      url: 'http://192.168.1.100/paypal/login.php?cmd=_login-run',
      badgeColor: 'border-rose-500/40 text-rose-400 bg-rose-950/30',
      description: 'Direct IPv4 address used as host targeting PayPal login credentials.'
    },
    {
      id: 'url-mal-subdomain',
      label: 'Microsoft Subdomain Cloaking (Malicious)',
      category: 'Malicious',
      url: 'http://login.microsoftonline.com.account-verification-alert.top/signin',
      badgeColor: 'border-rose-500/40 text-rose-400 bg-rose-950/30',
      description: 'Attackers chain microsoftonline.com as a subdomain prefix on untrusted .top domain.'
    }
  ],
  emails: [
    {
      id: 'email-safe-sprint',
      label: 'Sprint Planning Agenda (Safe)',
      category: 'Safe',
      badgeColor: 'border-emerald-500/40 text-emerald-400 bg-emerald-950/30',
      subject: 'Sprint Planning Agenda for Thursday',
      sender: 'team-lead@techcorp.internal',
      body: `Hi Team,

Please find the sprint planning agenda attached for this Thursday at 10 AM. We will review Jira tickets for the upcoming release, discuss deployment blockers, and allocate story points.

Best regards,
Alex Mercer
Engineering Lead`,
      description: 'Standard workplace communication with authentic internal sender and no panic triggers.'
    },
    {
      id: 'email-mal-paypal',
      label: 'PayPal Account Suspended (Malicious)',
      category: 'Malicious',
      badgeColor: 'border-rose-500/40 text-rose-400 bg-rose-950/30',
      subject: 'URGENT: Your PayPal Account Has Been Suspended!',
      sender: 'service-security-alert@gmail.com',
      body: `Dear Valued Customer,

We detected unauthorized access to your PayPal account from an unknown IP address in Moscow, Russia. Your account has been temporarily LOCKED. You must verify your identity immediately within 24 hours or your balance will be permanently confiscated.

Click the link below to verify your password and credit card number:
http://paypa1-security-verification.xyz/account-update

Failure to take immediate action will result in permanent account termination.

PayPal Security Dept.`,
      description: 'Critical phishing attack with sender mismatch (sent from @gmail.com), extreme urgency, and credential link.'
    },
    {
      id: 'email-mal-whaling',
      label: 'Executive CEO Wire Transfer (Malicious)',
      category: 'Malicious',
      badgeColor: 'border-rose-500/40 text-rose-400 bg-rose-950/30',
      subject: 'CONFIDENTIAL WIRE TRANSFER REQUEST',
      sender: 'ceo-office@company-exec-spoof.xyz',
      body: `Are you currently at your desk? I am in an urgent closed-door acquisition meeting and need an emergency wire transfer of $48,500 executed to an escrow account before 2:00 PM today. Do not call my phone as I cannot take calls right now. Send the bank confirmation directly to this email address.`,
      description: 'Business Email Compromise (BEC) whaling attack attempting financial fraud with strict secrecy.'
    },
    {
      id: 'email-mal-office365',
      label: 'Office 365 Password Expiry (Malicious)',
      category: 'Malicious',
      badgeColor: 'border-rose-500/40 text-rose-400 bg-rose-950/30',
      subject: 'Action Required: Office 365 Password Expiration Notice',
      sender: 'helpdesk-admin@temp-mail.org',
      body: `FINAL NOTICE: Your Microsoft 365 work password will expire in 1 hour!

To keep your current password and avoid losing email access, you must validate your credentials now at our portal:
http://office365-urgent-password-reset.icu/login.aspx?user=target

Do not ignore this warning.`,
      description: 'Credential harvesting attack using artificial 1-hour expiration deadline and spoofed helpdesk.'
    }
  ]
};

