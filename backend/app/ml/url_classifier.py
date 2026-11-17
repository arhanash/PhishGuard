import os
import joblib
import numpy as np
from .feature_extractor import extract_url_features
from .model_trainer import URL_MODEL_PATH, URL_FEATURE_NAMES_PATH, train_and_save_models

class URLClassifier:
    def __init__(self):
        train_and_save_models(force_retrain=False)
        self.model = joblib.load(URL_MODEL_PATH)
        self.feature_names = joblib.load(URL_FEATURE_NAMES_PATH)

    def analyze(self, url: str) -> dict:
        url = url.strip()
        features, meta = extract_url_features(url)

        # Prepare vector for ML model
        x_vec = np.array([[features[k] for k in self.feature_names]])
        ml_prob = float(self.model.predict_proba(x_vec)[0, 1])

        # Rule-based heuristics and indicators list
        indicators = []
        heuristic_score = 0.0

        # Indicator 1: Raw IP Address Hostname
        if meta["is_ip"]:
            impact = 35.0
            heuristic_score += impact
            indicators.append({
                "id": "URL-001",
                "category": "Host & Infrastructure",
                "name": "Direct IP Address Hostname",
                "severity": "High",
                "description": f"The URL uses a raw IP address ({meta['hostname']}) instead of a registered domain name. Legitimate services virtually never use raw IPs for public interfaces.",
                "score_impact": impact,
                "mitre_ref": "T1566.002"
            })

        # Indicator 2: High Entropy Hostname (DGA / Hash)
        if meta["hostname_entropy"] > 3.8:
            impact = 20.0
            heuristic_score += impact
            indicators.append({
                "id": "URL-002",
                "category": "Domain Analysis",
                "name": "High Hostname Shannon Entropy",
                "severity": "Medium",
                "description": f"Hostname entropy is {meta['hostname_entropy']}, indicating algorithmic randomness (Domain Generation Algorithm - DGA) or machine-generated domain names.",
                "score_impact": impact,
                "mitre_ref": "T1568.002"
            })

        # Indicator 3: Homoglyph / Punycode Deception
        if meta["has_punycode"]:
            impact = 40.0
            heuristic_score += impact
            indicators.append({
                "id": "URL-003",
                "category": "Evasion & Deception",
                "name": "Punycode / Homoglyph Attack (IDN Spoofing)",
                "severity": "Critical",
                "description": f"Hostname contains internationalized Punycode ('xn--') designed to spoof recognizable characters with Cyrillic or Greek lookalikes.",
                "score_impact": impact,
                "mitre_ref": "T1566.002"
            })

        # Indicator 4: Suspicious / High-Abuse TLD
        if meta["suspicious_tld"]:
            impact = 25.0
            heuristic_score += impact
            indicators.append({
                "id": "URL-004",
                "category": "Domain Reputation",
                "name": f"High-Abuse Top-Level Domain (.{meta['tld']})",
                "severity": "Medium",
                "description": f"The TLD '.{meta['tld']}' is statistically associated with high rates of malicious phishing and bulletproof hosting according to APWG threat telemetry.",
                "score_impact": impact,
                "mitre_ref": "T1583.001"
            })

        # Indicator 5: Deep Subdomain Stacking (Domain cloaking)
        if meta["subdomain_depth"] >= 3:
            impact = 25.0
            heuristic_score += impact
            indicators.append({
                "id": "URL-005",
                "category": "Structural Obfuscation",
                "name": "Excessive Subdomain Stacking",
                "severity": "High",
                "description": f"Detected {meta['subdomain_depth']} nested subdomain levels. Threat actors stack trusted brand names in subdomains (e.g. login.bank.com.attacker.com) to deceive users.",
                "score_impact": impact,
                "mitre_ref": "T1566.002"
            })

        # Indicator 6: Sensitive Brand / Financial Target Keywords
        if meta["matched_keywords"]:
            kws_str = ", ".join(meta["matched_keywords"][:5])
            impact = min(30.0, len(meta["matched_keywords"]) * 12.0)
            heuristic_score += impact
            indicators.append({
                "id": "URL-006",
                "category": "Credential Harvesting",
                "name": "Credential & Target Keywords Detected",
                "severity": "High" if len(meta["matched_keywords"]) > 1 else "Medium",
                "description": f"URL contains sensitive brand/authentication tokens: [{kws_str}]. Commonly used in fake credential harvesting portals.",
                "score_impact": impact,
                "mitre_ref": "T1598.003"
            })

        # Indicator 7: URL Shortener Masking
        if meta["is_shortener"]:
            impact = 18.0
            heuristic_score += impact
            indicators.append({
                "id": "URL-007",
                "category": "Evasion & Deception",
                "name": "URL Shortening Service Employed",
                "severity": "Medium",
                "description": f"Domain '{meta['hostname']}' is a URL shortener which masks the actual final destination, bypassing standard perimeter filtering.",
                "score_impact": impact,
                "mitre_ref": "T1566.002"
            })

        # Indicator 8: '@' Symbol in URL
        if meta["has_at_symbol"]:
            impact = 35.0
            heuristic_score += impact
            indicators.append({
                "id": "URL-008",
                "category": "Obfuscation",
                "name": "Embedded '@' Authentication Delimiter",
                "severity": "Critical",
                "description": "Browsers ignore strings before the '@' symbol in URLs, allowing attackers to fake the visible domain while steering traffic elsewhere.",
                "score_impact": impact,
                "mitre_ref": "T1566.002"
            })

        # Indicator 9: Unencrypted HTTP for sensitive context
        if meta["scheme"] == "http" and meta["matched_keywords"]:
            impact = 20.0
            heuristic_score += impact
            indicators.append({
                "id": "URL-009",
                "category": "Transport Security",
                "name": "Insecure HTTP Protocol with Auth Keywords",
                "severity": "Medium",
                "description": "The URL requests sensitive authentication keywords over unencrypted plaintext HTTP, exposing user credentials to intercept or MITM attacks.",
                "score_impact": impact,
                "mitre_ref": "T1040"
            })

        # Indicator 10: Abnormal URL Length
        if features["url_len"] > 95:
            impact = 15.0
            heuristic_score += impact
            indicators.append({
                "id": "URL-010",
                "category": "Lexical Anomaly",
                "name": "Excessive URL Length",
                "severity": "Low",
                "description": f"Total URL length is {features['url_len']} characters, which often correlates with session hijacking tokens or obfuscated redirects.",
                "score_impact": impact,
                "mitre_ref": "T1566.002"
            })

        # Ensemble Score Formulation:
        # Weighted combination of ML Random Forest probability (55%) and Rule Heuristics (45%)
        # with critical override if multiple critical indicators trigger
        ml_score_contrib = ml_prob * 100.0
        heuristic_clamped = min(100.0, heuristic_score)

        if len(indicators) == 0:
            final_risk = min(15.0, ml_score_contrib * 0.3)
        else:
            final_risk = (0.50 * ml_score_contrib) + (0.50 * heuristic_clamped)

        # Ensure critical flags guarantee high risk
        if any(ind["severity"] == "Critical" for ind in indicators) and final_risk < 70.0:
            final_risk = max(72.0, final_risk + 25.0)

        final_risk = round(max(0.0, min(100.0, final_risk)), 1)

        # Classification
        if final_risk <= 30.0:
            classification = "Safe"
            summary = "No significant phishing or malicious patterns detected. The URL exhibits normal lexical structure and trusted domain signatures."
        elif final_risk <= 69.0:
            classification = "Suspicious"
            summary = "Suspicious markers identified. The URL exhibits anomalous attributes such as keyword stuffing, abnormal TLD, or obfuscated paths."
        else:
            classification = "Malicious"
            summary = "High probability of Phishing attack. Critical indicators detected including domain spoofing, suspicious infrastructure, or credential harvesting triggers."

        # Recommendations
        recommendations = self._generate_recommendations(classification, indicators, meta)

        return {
            "risk_score": final_risk,
            "classification": classification,
            "threat_summary": summary,
            "threat_indicators": indicators,
            "detailed_analysis": {
                "ml_phishing_probability": round(ml_prob * 100.0, 1),
                "heuristic_score": round(heuristic_clamped, 1),
                "lexical_features": features,
                "domain_metadata": meta,
            },
            "security_recommendations": recommendations,
        }

    def _generate_recommendations(self, classification: str, indicators: list, meta: dict) -> list:
        recs = []
        if classification == "Malicious":
            recs.append("BLOCK ACCESS: Do not visit this URL or submit any credentials, tokens, or personal information.")
            recs.append("REPORT PHISH: Submit this domain to Google Safe Browsing, PhishTank, and CISA reporting portals.")
            recs.append("FIREWALL RULE: Add the domain and host IP address to corporate perimeter and DNS sinkhole blacklists.")
            if meta.get("is_ip"):
                recs.append("IP AUDIT: Block outbound perimeter connections directly to unauthenticated public IP addresses.")
        elif classification == "Suspicious":
            recs.append("PROCEED WITH CAUTION: Open only in an isolated sandbox or headless browser environment.")
            recs.append("VERIFY IDENTITY: Navigate directly to the official organization website by typing the address manually.")
            recs.append("CHECK CERTIFICATE: Inspect the SSL/TLS digital certificate issuer and domain ownership details.")
        else:
            recs.append("URL appears clean. Maintain standard zero-trust browsing vigilance.")
            recs.append("Ensure multi-factor authentication (MFA) is enabled on all sensitive online accounts.")

        recs.append("Never reuse corporate or primary passwords across multiple web portals.")
        return recs

