import socket
from urllib.parse import urlparse
from sqlalchemy.orm import Session
import json

from ..ml.url_classifier import URLClassifier
from ..models import ScanRecord

url_classifier_instance = URLClassifier()

def scan_url(url: str, db: Session = None) -> dict:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # ML & Heuristic Analysis
    analysis_result = url_classifier_instance.analyze(url)

    # DNS Resolution Check (Fast timeout check)
    domain_to_check = analysis_result["detailed_analysis"]["domain_metadata"]["hostname"]
    dns_status = "Unknown"
    ip_resolved = None
    try:
        ip_resolved = socket.gethostbyname(domain_to_check)
        dns_status = "Resolved"
    except socket.gaierror:
        dns_status = "NXDOMAIN (Non-existent Domain or Blocked)"
    except Exception:
        dns_status = "Lookup Timeout / Unreachable"

    analysis_result["detailed_analysis"]["dns_info"] = {
        "status": dns_status,
        "resolved_ip": ip_resolved
    }

    # Persist in SQLite database
    scan_id = None
    if db:
        record = ScanRecord(
            scan_type="url",
            target=url,
            risk_score=analysis_result["risk_score"],
            classification=analysis_result["classification"],
            threat_summary=analysis_result["threat_summary"],
            threat_indicators=json.dumps(analysis_result["threat_indicators"]),
            detailed_analysis=json.dumps(analysis_result["detailed_analysis"]),
            security_recommendations=json.dumps(analysis_result["security_recommendations"]),
            raw_input=url,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        scan_id = record.id

    analysis_result["id"] = scan_id
    analysis_result["target"] = url
    analysis_result["scan_type"] = "url"

    return analysis_result

