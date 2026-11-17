# PhishGuard – AI-Powered Phishing URL and Email Detection System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB.svg)](https://react.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-v4-38B2AC.svg)](https://tailwindcss.com/)
[![Scikit--Learn](https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-F7931E.svg)](https://scikit-learn.org/)
[![Database](https://img.shields.io/badge/Database-SQLite-003B57.svg)](https://www.sqlite.org/)
[![Cybersecurity](https://img.shields.io/badge/Domain-B.Tech%20Cybersecurity-red.svg)]()

> **PhishGuard** is an enterprise-grade cybersecurity web application designed to detect, classify, and explain phishing attacks in website URLs and email communications. Combining Machine Learning (Random Forest and TF-IDF NLP) with heuristic cybersecurity rules, PhishGuard provides actionable risk scoring (0–100%), threat breakdowns mapped to the **MITRE ATT&CK** framework, persistent scan history, interactive analytics, and downloadable forensic reports (PDF & TXT).

---

## 🛡️ Key Features

1. **AI-Powered URL Phishing Detection**
   - Extracts 22 lexical, structural, and semantic features.
   - Evaluates Shannon Entropy ($H > 3.8$ bits) for Domain Generation Algorithms (DGA) and hex hashes.
   - Detects IDN Homoglyphs and Punycode spoofing (`xn--`).
   - Identifies direct IPv4/IPv6 host addresses, URL shortener cloaking, deep subdomain stacking, and high-abuse Top-Level Domains (`.xyz`, `.top`, `.buzz`, `.tk`, etc.).
   - Fast socket-level DNS resolution checks (`Resolved` vs `NXDOMAIN`).

2. **AI-Powered Email Phishing & BEC Detection**
   - Natural Language Processing (NLP) with TF-IDF vectorization.
   - Unmasks sender display name impersonation and header mismatches.
   - Quantifies emotional coercion and artificial urgency triggers (*24 hours*, *immediate action required*, *account suspended*).
   - Detects credential theft solicitations (password, PIN, seed phrase, SSN).
   - Flags Business Email Compromise (BEC) wire transfers and crypto ransomware demands.
   - Recursively extracts and scans embedded hyperlinks inside the email body.

3. **Calibrated Risk Scoring (0–100%) & 3-Tier Classification**
   - **Safe (0–30%)**: Verified benign baseline, established domain signatures.
   - **Suspicious (31–69%)**: Anomalous lexical tokens, shortened links, or emotional pressure cues.
   - **Malicious (70–100%)**: Active phishing infrastructure, homoglyph deception, or credential harvesting payloads.

4. **Forensic Threat Explanations & MITRE ATT&CK Mapping**
   - Detailed threat breakdown cards displaying Severity (*Critical*, *High*, *Medium*, *Low*), Category, Point Contribution, and MITRE Technique reference codes (`T1566.001`, `T1566.002`, `T1598.003`, `T1568.002`, `T1583.001`).

5. **Scan History & Audit Logs**
   - Persistent SQLite storage (`phishguard.db`) via SQLAlchemy ORM.
   - Filter by modality (URL vs Email) or classification (*Safe*, *Suspicious*, *Malicious*).
   - Search targets, drill into historical reports, or purge audit logs.

6. **Threat Intelligence & Analytics Dashboard**
   - Real-time KPI counters: Total Scans, Detection Rates, Mean Threat Index.
   - Interactive charts via **Recharts**:
     - *Risk Level Distribution* (Donut Chart)
     - *Threat Vectors Triggered by Category* (Bar Chart)
     - *Recent Threat Audit Feed* with instant drill-down.

7. **Downloadable Forensic Reports**
   - **Official PDF Report**: Styled with forensic timestamps, SHA-256 target hash, risk gauges, indicators, and mitigation steps.
   - **Forensic TXT Report**: Clean formatting for SIEM ingestion and SOC incident tickets.
   - **Raw JSON**: Machine-readable format for API integrations.

8. **Enterprise Security Playbook & Pre-Built Test Scenarios**
   - Educational cybersecurity reference covering phishing anatomy, incident response phases, and defense-in-depth policies.
   - 1-Click interactive sample test cases for immediate presentation.

---

## 🏛️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React + Tailwind CSS)                 │
│  ┌──────────────┐ ┌───────────────┐ ┌─────────────┐ ┌───────────────┐  │
│  │ URL Scanner  │ │ Email Scanner │ │ Analytics   │ │ Scan History  │  │
│  │  Interface   │ │   Interface   │ │  Dashboard  │ │  & Playbook   │  │
│  └──────┬───────┘ └───────┬───────┘ └──────┬──────┘ └───────┬───────┘  │
└─────────┼─────────────────┼────────────────┼────────────────┼──────────┘
          │                 │                │                │
          ▼                 ▼                ▼                ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        FASTAPI REST BACKEND CORE                       │
│  /api/scan/url       /api/scan/email       /api/dashboard/stats        │
│  /api/history        /api/report/download  /api/sample-cases           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
          ┌─────────────────────────┴────────────────────────┐
          ▼                                                  ▼
┌───────────────────────────────────┐    ┌────────────────────────────────┐
│      DETECTION ENGINE PIPELINE    │    │        DATABASE & ORM          │
│                                   │    │                                │
│ 1. Feature Extractor (22 feats)   │    │ SQLite Database                │
│ 2. Shannon Entropy & Lexical Eval │    │ `phishguard.db`                │
│ 3. ML Random Forest Classifier    │    │                                │
│ 4. NLP TF-IDF Vectorizer + Model  │    │ SQLAlchemy Models              │
│ 5. Rule Heuristic Ensemble Engine │    │ ScanRecord (Audit History)     │
│ 6. MITRE ATT&CK Reference Mapper  │    │                                │
└───────────────────────────────────┘    └────────────────────────────────┘
```

---

## 🧪 Detection Methodology

PhishGuard employs a **hybrid ensemble architecture**:

$$\text{Final Risk Score} = (0.50 \times \text{ML Probability}) + (0.50 \times \text{Heuristic Score})$$

- **Critical Override**: If critical indicators trigger (e.g., direct IP hosting, Punycode IDN spoofing, or verified credential theft solicitations), the system automatically elevates the risk score to $\ge 72\%$ (*Malicious*).
- **Shannon Entropy Calculation**:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  Measures randomness in domain labels to intercept machine-generated algorithms (DGAs).

---

## 📁 Project Directory Structure

```
SRMP/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI application & SPA static routing
│   │   ├── database.py          # SQLite engine and session factory
│   │   ├── models.py            # SQLAlchemy ScanRecord schema
│   │   ├── schemas.py           # Pydantic request & response models
│   │   ├── ml/
│   │   │   ├── feature_extractor.py # 22-dimensional URL & Email feature extraction
│   │   │   ├── sample_datasets.py   # Curated phishing & benign datasets
│   │   │   ├── model_trainer.py     # Random Forest & TF-IDF model training
│   │   │   ├── url_classifier.py    # URL ML inference & heuristic ensemble
│   │   │   └── email_classifier.py  # Email NLP inference & recursive URL scan
│   │   ├── services/
│   │   │   ├── url_scanner.py       # High-level URL scanner orchestrator
│   │   │   ├── email_scanner.py     # Email scanner orchestrator
│   │   │   └── report_generator.py  # Text and PDF report generation
│   │   └── data/
│   │       ├── phishguard.db        # SQLite database
│   │       ├── url_model.joblib     # Serialized Random Forest model
│   │       ├── email_model.joblib   # Serialized Email NLP model
│   │       └── email_vectorizer.joblib
│   ├── requirements.txt
│   └── test_backend.py          # Automated backend verification test suite
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.jsx           # Cyber-themed navigation with live status
│   │   │   ├── UrlScanner.jsx       # URL scanner with 1-click test cases
│   │   │   ├── EmailScanner.jsx     # Email scanner with header & body inputs
│   │   │   ├── CyberScannerAnimation.jsx # Animated cyber radar telemetry
│   │   │   ├── ThreatResults.jsx    # Visual risk gauge & forensic indicator cards
│   │   │   ├── AnalyticsView.jsx    # Interactive Recharts KPI dashboard
│   │   │   ├── HistoryDashboard.jsx # Persistent audit history & search
│   │   │   └── SecurityGuide.jsx    # Academic reference & incident playbook
│   │   ├── services/
│   │   │   └── api.js               # Frontend-to-backend API client
│   │   ├── sampleData.js            # Sample test scenarios
│   │   ├── App.jsx                  # Main application container
│   │   ├── index.css                # Tailwind CSS + Cyber glow styling
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
├── run_phishguard.py            # One-command unified application launcher
├── start.bat                    # Double-click Windows startup script
└── README.md                    # Project documentation
```

---

## 🚀 Quickstart & Local Setup

### Prerequisites
- Python 3.10+
- Node.js v18+ and npm (only needed if rebuilding the frontend)

### Option 1: One-Command Launch (Recommended)
Simply run the launcher script from the project root:
```bash
python run_phishguard.py
```
*On Windows, you can also double-click `start.bat`.*

This script automatically:
1. Verifies/trains the Machine Learning models.
2. Initializes the SQLite database.
3. Serves the full React application on **http://127.0.0.1:8000/**.
4. Opens your default web browser automatically.

---

### Option 2: Running Backend & Frontend in Development Mode

**Terminal 1 — Backend API:**
```bash
python -m pip install -r backend/requirements.txt
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Terminal 2 — React Frontend (Vite Dev Server with Hot-Reload):**
```bash
cd frontend
npm install
npm run dev
```
Open **http://localhost:5173/** in your browser. (All `/api` requests are proxied automatically to `http://127.0.0.1:8000`).

---

## 🧪 Automated Testing

PhishGuard includes a complete automated test suite testing the detection logic, API contracts, database persistence, and report generation:

```bash
python backend/test_backend.py
```

**Sample Output:**
```
--- Running PhishGuard Backend Test Suite ---
✓ Test Health Check Passed
✓ Test Legitimate URL Passed: Google.com -> Safe (0.6%)
✓ Test Malicious IP URL Passed: -> Malicious (87.0%)
✓ Test Malicious Typosquatting URL Passed: -> Malicious (97.5%)
✓ Test Legitimate Email Passed: -> Safe (13.6%)
✓ Test Malicious Email Passed: -> Malicious (92.3%)
✓ Test Dashboard Stats Passed: Total 10 scans recorded
✓ Test Download Report Passed: Generated TXT and JSON forensic reports for scan #10

✓ ALL TESTS PASSED SUCCESSFULLY!
```

---

## 🎯 Pre-Built Test Cases for Demonstration

| Category | Target / Scenario | Expected Verdict | Score | Key Triggered Indicators |
|---|---|---|---|---|
| **URL (Safe)** | `https://www.google.com` | **Safe** | 0.6% | Clean lexical structure, valid HTTPS, nominal entropy. |
| **URL (Safe)** | `https://github.com/torvalds/linux` | **Safe** | 0.6% | Verified repository path, benign TLD reputation. |
| **URL (Suspicious)** | `http://bit.ly/3xFakeBankLoginPhish` | **Suspicious** | 35.0% | URL shortener cloaking true destination, unencrypted HTTP. |
| **URL (Malicious)** | `http://paypa1-security-verification.xyz/account-update` | **Malicious** | 97.5% | Typosquatting (`paypa1`), high-abuse `.xyz` TLD, auth keywords. |
| **URL (Malicious)** | `http://192.168.1.100/paypal/login.php?cmd=_login-run` | **Malicious** | 87.0% | Direct IP hostname (`URL-001`), target brand keywords. |
| **URL (Malicious)** | `http://login.microsoftonline.com.account-verification-alert.top/signin` | **Malicious** | 97.5% | Deep subdomain cloaking, high-abuse `.top` TLD, auth tokens. |
| **Email (Safe)** | Sprint Planning Agenda | **Safe** | 13.6% | Authentic internal sender, normal tone, zero panic indicators. |
| **Email (Malicious)** | Urgent PayPal Suspension Alert | **Malicious** | 92.3% | Sender spoofing (`@gmail.com`), 24h deadline, malicious embedded link. |
| **Email (Malicious)** | Confidential CEO Wire Transfer (Whaling) | **Malicious** | 76.5% | Business Email Compromise (BEC), secret wire request, urgency. |
| **Email (Malicious)** | Office 365 Password Expiration Notice | **Malicious** | 89.0% | 1-hour expiration deadline, disposable domain, credential harvester. |

---

## 🎓 Academic Presentation & Viva Q&A Guide

1. **Why use an ensemble rather than pure Deep Learning?**
   - Pure neural networks or LLMs act as black boxes with high inference latency and vulnerability to hallucinations or adversarial perturbations. PhishGuard combines Random Forest probability with deterministic heuristics to deliver **explainable AI (XAI)**: every point in the risk score maps to an auditable threat indicator with MITRE ATT&CK correlation.

2. **How does PhishGuard handle zero-day phishing domains?**
   - Rather than relying solely on static reputation blocklists, PhishGuard inspects structural intrinsic traits: Shannon entropy, lexical character distributions, subdomain nesting depth, Punycode encoding, and protocol insecurity.

3. **How does the email scanner handle links inside emails?**
   - The email detection engine extracts every embedded hyperlink using regular expressions and recursively passes them through the URL detection engine. If an embedded link is flagged as malicious, it severely escalates the parent email's threat score.

---

## ⚖️ License
Developed for educational and academic cybersecurity research purposes. Distributed under the MIT License.

