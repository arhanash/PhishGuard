import os
import joblib
from .feature_extractor import extract_email_features
from .model_trainer import EMAIL_MODEL_PATH, EMAIL_VEC_PATH, train_and_save_models
from .url_classifier import URLClassifier

class EmailClassifier:
    def __init__(self, url_classifier: URLClassifier = None):
        train_and_save_models(force_retrain=False)
        self.model = joblib.load(EMAIL_MODEL_PATH)
        self.vectorizer = joblib.load(EMAIL_VEC_PATH)
        self.url_classifier = url_classifier or URLClassifier()

    def analyze(self, raw_content: str, subject: str = "", sender: str = "") -> dict:
        features, meta, combined_text = extract_email_features(raw_content, subject, sender)

        # 1. ML TF-IDF Classification
        x_tfidf = self.vectorizer.transform([combined_text])
        ml_prob = float(self.model.predict_proba(x_tfidf)[0, 1])

        indicators = []
        heuristic_score = 0.0

        # Indicator 1: Brand Impersonation / Sender Mismatch
        if meta["impersonation_flag"]:
            impact = 35.0
            heuristic_score += impact
            brand_name = meta["impersonated_brand"].title()
            indicators.append({
                "id": "EML-001",
                "category": "Sender Identity Spoofing",
                "name": f"Impersonation of {brand_name}",
                "severity": "Critical",
                "description": f"The email sender claims to represent {brand_name}, but originates from an unauthorized, mismatched, or free webmail domain ({meta['sender']}).",
                "score_impact": impact,
                "mitre_ref": "T1566.001"
            })

        # Indicator 2: High Urgency / Coercive Language
        if meta["matched_urgency"]:
            matched_count = len(meta["matched_urgency"])
            impact = min(30.0, matched_count * 10.0)
            heuristic_score += impact
            indicators.append({
                "id": "EML-002",
                "category": "Social Engineering",
                "name": "Psychological Urgency & Fear Triggers",
                "severity": "High" if matched_count >= 2 else "Medium",
                "description": f"Coercive urgency tactics detected: [{', '.join(meta['matched_urgency'][:4])}]. Attackers use artificial time pressure to bypass critical thinking.",
                "score_impact": impact,
                "mitre_ref": "T1566"
            })

        # Indicator 3: Credential Harvesting Cues
        if meta["matched_credentials"]:
            matched_count = len(meta["matched_credentials"])
            impact = min(35.0, matched_count * 12.0)
            heuristic_score += impact
            indicators.append({
                "id": "EML-003",
                "category": "Credential Theft",
                "name": "Direct Credential / PII Harvesting Solicitations",
                "severity": "Critical",
                "description": f"Email solicits sensitive credentials or personally identifiable information (PII): [{', '.join(meta['matched_credentials'][:3])}]. Legitimate firms never request passwords via email.",
                "score_impact": impact,
                "mitre_ref": "T1598.003"
            })

        # Indicator 4: Financial Fraud / Wire Transfer / Crypto Extortion
        if meta["matched_financial"]:
            impact = min(35.0, len(meta["matched_financial"]) * 14.0)
            heuristic_score += impact
            indicators.append({
                "id": "EML-004",
                "category": "Financial Fraud & BEC",
                "name": "Financial Transfer / BEC / Ransom Solicitations",
                "severity": "High",
                "description": f"Detected Business Email Compromise (BEC) or extortion markers: [{', '.join(meta['matched_financial'][:3])}].",
                "score_impact": impact,
                "mitre_ref": "T1566.001"
            })

        # Indicator 5: Dangerous Attachment Extensions
        if meta["matched_extensions"]:
            impact = 35.0
            heuristic_score += impact
            indicators.append({
                "id": "EML-005",
                "category": "Malicious Payload",
                "name": "High-Risk Executable / Container File References",
                "severity": "Critical",
                "description": f"Email references high-risk executable or archive formats: [{', '.join(meta['matched_extensions'])}], frequently used to deploy ransomware and keyloggers.",
                "score_impact": impact,
                "mitre_ref": "T1566.001"
            })

        # Indicator 6: Excessive Capitalization and Punctuation
        if meta["caps_ratio"] > 0.22 and len(raw_content) > 60:
            impact = 10.0
            heuristic_score += impact
            indicators.append({
                "id": "EML-006",
                "category": "Stylometry & Sentiment",
                "name": "Abnormal Capitalization Ratio",
                "severity": "Low",
                "description": f"Uppercase letter ratio is {int(meta['caps_ratio'] * 100)}%, indicating aggressive scam styling or stress-inducing visual shouting.",
                "score_impact": impact,
                "mitre_ref": "T1566"
            })

        # Indicator 7: Embedded URLs Deep Scan
        embedded_url_results = []
        if meta["found_urls"]:
            for u in meta["found_urls"][:3]: # scan up to 3 embedded URLs
                u_res = self.url_classifier.analyze(u)
                embedded_url_results.append({
                    "url": u,
                    "risk_score": u_res["risk_score"],
                    "classification": u_res["classification"]
                })
                if u_res["classification"] == "Malicious":
                    impact = 40.0
                    heuristic_score += impact
                    indicators.append({
                        "id": "EML-007",
                        "category": "Embedded Threat Links",
                        "name": f"Malicious Embedded Hyperlink ({u_res['risk_score']}%)",
                        "severity": "Critical",
                        "description": f"Contains embedded phishing URL: '{u}'. Leads to known phishing or credential theft infrastructure.",
                        "score_impact": impact,
                        "mitre_ref": "T1566.002"
                    })
                elif u_res["classification"] == "Suspicious":
                    impact = 20.0
                    heuristic_score += impact
                    indicators.append({
                        "id": "EML-008",
                        "category": "Embedded Threat Links",
                        "name": "Suspicious Embedded Hyperlink",
                        "severity": "Medium",
                        "description": f"Contains link with suspicious structural traits: '{u}'.",
                        "score_impact": impact,
                        "mitre_ref": "T1566.002"
                    })

        # Ensemble Score Formulation
        ml_score_contrib = ml_prob * 100.0
        heuristic_clamped = min(100.0, heuristic_score)

        if len(indicators) == 0:
            final_risk = min(15.0, ml_score_contrib * 0.35)
        else:
            final_risk = (0.50 * ml_score_contrib) + (0.50 * heuristic_clamped)

        # Critical triggers guarantee malicious tier
        if any(ind["severity"] == "Critical" for ind in indicators) and final_risk < 70.0:
            final_risk = max(72.0, final_risk + 25.0)

        final_risk = round(max(0.0, min(100.0, final_risk)), 1)

        # Classification
        if final_risk <= 30.0:
            classification = "Safe"
            summary = "Email appears legitimate. Normal workplace or transactional phrasing with no detected social engineering vectors or malicious links."
        elif final_risk <= 69.0:
            classification = "Suspicious"
            summary = "Suspicious social engineering signals or unverified sender cues identified. Exercise caution before trusting instructions."
        else:
            classification = "Malicious"
            summary = "Critical Phishing or Social Engineering attack identified! High risk of credential harvesting, BEC wire fraud, or malicious payload distribution."

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
                "features": features,
                "metadata": meta,
                "embedded_urls_analysis": embedded_url_results
            },
            "security_recommendations": recommendations,
        }

    def _generate_recommendations(self, classification: str, indicators: list, meta: dict) -> list:
        recs = []
        if classification == "Malicious":
            recs.append("DO NOT INTERACT: Do not reply, click any embedded links, or download attachments.")
            recs.append("REPORT TO SOC / IT: Forward as an RFC 822 attachment to your organization's security operations center (SOC).")
            recs.append("RESET CREDENTIALS: If you clicked any links or entered passwords, immediately change your account password and revoke active sessions.")
            if meta.get("impersonation_flag"):
                recs.append("OUT-OF-BAND VERIFICATION: Verify any urgent requests through a verified phone number or separate internal communication channel.")
        elif classification == "Suspicious":
            recs.append("INSPECT SENDER HEADERS: Check the Return-Path and SPF/DKIM/DMARC status to confirm email authenticity.")
            recs.append("AVOID SENSITIVE DISCLOSURE: Do not transmit financial details, OTPs, or employee PII via email.")
            recs.append("PREVIEW LINKS: Hover over hyperlinks to confirm the true destination URL matches the displayed anchor text.")
        else:
            recs.append("Email appears normal. Always follow standard organizational phishing reporting procedures.")
            recs.append("Never share one-time authentication passcodes (2FA/MFA) with anyone.")

        return recs

