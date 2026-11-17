import hashlib
from datetime import datetime, timezone

def generate_text_report(scan_data: dict) -> str:
    """
    Generates an official cybersecurity forensic scan report in formatted text.
    Suitable for academic project documentation, SOC triage, and incident response tickets.
    """
    target = scan_data.get("target", "N/A")
    scan_type = scan_data.get("scan_type", "URL").upper()
    risk_score = scan_data.get("risk_score", 0.0)
    classification = scan_data.get("classification", "Unknown").upper()
    threat_summary = scan_data.get("threat_summary", "No details available.")
    timestamp = scan_data.get("timestamp") or datetime.now(timezone.utc).isoformat()
    scan_id = scan_data.get("id", "N/A")

    # Generate SHA-256 target hash for forensic chain-of-custody
    target_hash = hashlib.sha256(str(target).encode("utf-8")).hexdigest()

    indicators = scan_data.get("threat_indicators", [])
    recommendations = scan_data.get("security_recommendations", [])
    detailed = scan_data.get("detailed_analysis", {})

    lines = [
        "================================================================================",
        "                     PHISHGUARD CYBERSECURITY THREAT REPORT                     ",
        "         AI-Powered Phishing URL and Email Threat Forensic Assessment           ",
        "================================================================================",
        f" Report ID         : PG-SEC-{scan_id}",
        f" Scan Type         : {scan_type} ANALYSIS",
        f" Generated At      : {timestamp}",
        f" Target Entity     : {target}",
        f" Target SHA-256    : {target_hash}",
        "--------------------------------------------------------------------------------",
        " THREAT ASSESSMENT SUMMARY",
        "--------------------------------------------------------------------------------",
        f" Risk Classification : [{classification}]",
        f" Risk Score          : {risk_score} / 100",
        f" ML Confidence       : {detailed.get('ml_phishing_probability', 'N/A')}%",
        f" Heuristic Score     : {detailed.get('heuristic_score', 'N/A')}%",
        f" Executive Verdict   : {threat_summary}",
        "--------------------------------------------------------------------------------",
        " FORENSIC THREAT INDICATORS DETECTED",
        "--------------------------------------------------------------------------------",
    ]

    if not indicators:
        lines.append("  [✓] No malicious indicators triggered. System parameters are nominal.")
    else:
        for idx, ind in enumerate(indicators, 1):
            lines.append(f"  {idx}. [{ind.get('severity', 'UNKNOWN').upper()}] {ind.get('name', 'Indicator')}")
            lines.append(f"     ID / MITRE  : {ind.get('id', 'N/A')} ({ind.get('mitre_ref', 'N/A')})")
            lines.append(f"     Category    : {ind.get('category', 'General')}")
            lines.append(f"     Description : {ind.get('description', '')}")
            lines.append(f"     Impact      : +{ind.get('score_impact', 0)} pts")
            lines.append("")

    lines.extend([
        "--------------------------------------------------------------------------------",
        " RECOMMENDED MITIGATION ACTIONS",
        "--------------------------------------------------------------------------------",
    ])

    for idx, rec in enumerate(recommendations, 1):
        lines.append(f"  [{idx}] {rec}")

    lines.extend([
        "",
        "================================================================================",
        " End of Forensic Report - PhishGuard AI Cyber Defense Engine                    ",
        "================================================================================",
    ])

    return "\n".join(lines)

