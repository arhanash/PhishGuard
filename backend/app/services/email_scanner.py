from sqlalchemy.orm import Session
import json

from ..ml.email_classifier import EmailClassifier
from ..ml.url_classifier import URLClassifier
from ..models import ScanRecord

email_classifier_instance = EmailClassifier()

def scan_email(raw_content: str, subject: str = "", sender: str = "", db: Session = None) -> dict:
    analysis_result = email_classifier_instance.analyze(
        raw_content=raw_content,
        subject=subject,
        sender=sender
    )

    # Preview target title for summary
    target_summary = subject.strip() if subject.strip() else (raw_content.strip()[:80] + "...")

    # Persist in database
    scan_id = None
    if db:
        record = ScanRecord(
            scan_type="email",
            target=target_summary,
            risk_score=analysis_result["risk_score"],
            classification=analysis_result["classification"],
            threat_summary=analysis_result["threat_summary"],
            threat_indicators=json.dumps(analysis_result["threat_indicators"]),
            detailed_analysis=json.dumps(analysis_result["detailed_analysis"]),
            security_recommendations=json.dumps(analysis_result["security_recommendations"]),
            raw_input=raw_content,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        scan_id = record.id

    analysis_result["id"] = scan_id
    analysis_result["target"] = target_summary
    analysis_result["scan_type"] = "email"

    return analysis_result

