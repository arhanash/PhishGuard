from datetime import datetime, timezone
from typing import Optional, List
import json
import os

from fastapi import FastAPI, Depends, HTTPException, Query, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc

from .database import engine, Base, get_db
from .models import ScanRecord
from .schemas import (
    URLScanRequest,
    EmailScanRequest,
    ScanResultResponse,
    DashboardStatsResponse,
)
from .services.url_scanner import scan_url
from .services.email_scanner import scan_email
from .services.report_generator import generate_text_report
from .ml.model_trainer import train_and_save_models

# Ensure database tables are created
Base.metadata.create_all(bind=engine)

# Initialize and verify ML models
train_and_save_models(force_retrain=False)

app = FastAPI(
    title="PhishGuard API",
    description="AI-Powered Phishing URL and Email Detection Engine",
    version="1.0.0"
)

# CORS setup for Vite frontend (running on port 5173 or other local dev origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "service": "PhishGuard Threat Defense Core",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0"
    }

@app.post("/api/scan/url", response_model=ScanResultResponse)
def api_scan_url(payload: URLScanRequest, db: Session = Depends(get_db)):
    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")
    
    result = scan_url(payload.url.strip(), db=db)
    result["timestamp"] = datetime.now(timezone.utc).isoformat()
    return result

@app.post("/api/scan/email", response_model=ScanResultResponse)
def api_scan_email(payload: EmailScanRequest, db: Session = Depends(get_db)):
    if not payload.raw_content or not payload.raw_content.strip():
        raise HTTPException(status_code=400, detail="Email content cannot be empty.")

    result = scan_email(
        raw_content=payload.raw_content.strip(),
        subject=payload.subject or "",
        sender=payload.sender or "",
        db=db
    )
    result["timestamp"] = datetime.now(timezone.utc).isoformat()
    return result

@app.get("/api/history")
def get_history(
    scan_type: Optional[str] = None,
    classification: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(ScanRecord)

    if scan_type and scan_type.lower() != "all":
        query = query.filter(ScanRecord.scan_type == scan_type.lower())

    if classification and classification.lower() != "all":
        query = query.filter(ScanRecord.classification == classification.capitalize())

    if search:
        search_fmt = f"%{search.strip()}%"
        query = query.filter(
            (ScanRecord.target.ilike(search_fmt)) |
            (ScanRecord.threat_summary.ilike(search_fmt))
        )

    total_count = query.count()
    records = query.order_by(desc(ScanRecord.timestamp)).offset(offset).limit(limit).all()

    return {
        "total": total_count,
        "items": [r.to_dict() for r in records]
    }

@app.get("/api/history/{scan_id}")
def get_scan_by_id(scan_id: int, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return record.to_dict()

@app.delete("/api/history/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    db.delete(record)
    db.commit()
    return {"message": f"Scan record #{scan_id} deleted successfully."}

@app.delete("/api/history")
def clear_all_history(db: Session = Depends(get_db)):
    deleted_count = db.query(ScanRecord).delete()
    db.commit()
    return {"message": f"Cleared {deleted_count} scan records."}

@app.get("/api/dashboard/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    all_records = db.query(ScanRecord).all()

    total_scans = len(all_records)
    safe_scans = sum(1 for r in all_records if r.classification == "Safe")
    suspicious_scans = sum(1 for r in all_records if r.classification == "Suspicious")
    malicious_scans = sum(1 for r in all_records if r.classification == "Malicious")
    url_scans = sum(1 for r in all_records if r.scan_type == "url")
    email_scans = sum(1 for r in all_records if r.scan_type == "email")

    avg_score = (sum(r.risk_score for r in all_records) / total_scans) if total_scans > 0 else 0.0

    recent = db.query(ScanRecord).order_by(desc(ScanRecord.timestamp)).limit(8).all()

    # Attack category distribution from threat indicators
    categories = {}
    for r in all_records:
        try:
            inds = json.loads(r.threat_indicators) if r.threat_indicators else []
            for ind in inds:
                cat = ind.get("category", "General")
                categories[cat] = categories.get(cat, 0) + 1
        except Exception:
            continue

    if not categories:
        categories = {
            "Domain Spoofing": 0,
            "Credential Harvesting": 0,
            "Urgency / Social Eng": 0,
            "Infrastructure Anomalies": 0,
            "Evasion / Cloaking": 0,
        }

    return {
        "total_scans": total_scans,
        "safe_scans": safe_scans,
        "suspicious_scans": suspicious_scans,
        "malicious_scans": malicious_scans,
        "avg_risk_score": round(avg_score, 1),
        "url_scans_count": url_scans,
        "email_scans_count": email_scans,
        "recent_scans": [r.to_dict() for r in recent],
        "attack_type_distribution": categories
    }

@app.get("/api/report/{scan_id}/download")
def download_report(scan_id: int, format: str = "txt", db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    record_dict = record.to_dict()

    if format.lower() == "json":
        json_content = json.dumps(record_dict, indent=2)
        return Response(
            content=json_content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="phishguard_report_{scan_id}.json"'}
        )

    # Default to formatted forensic text
    text_report = generate_text_report(record_dict)
    return Response(
        content=text_report,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="phishguard_report_{scan_id}.txt"'}
    )

@app.get("/api/sample-cases")
def get_sample_cases():
    """Curated test cases for academic evaluation and live demonstration."""
    return {
        "urls": [
            {
                "label": "Legitimate - Google Official",
                "url": "https://www.google.com",
                "expected": "Safe",
                "description": "Standard trusted search engine domain with HTTPS and clean structure."
            },
            {
                "label": "Legitimate - GitHub Repository",
                "url": "https://github.com/torvalds/linux",
                "expected": "Safe",
                "description": "Legitimate developer portal with HTTPS and established domain reputation."
            },
            {
                "label": "Suspicious - Bitly Shortened URL",
                "url": "http://bit.ly/3xFakeBankLoginPhish",
                "expected": "Suspicious",
                "description": "Shortened link hiding true destination over unencrypted HTTP."
            },
            {
                "label": "Malicious - PayPal Typosquatting (.xyz)",
                "url": "http://paypa1-security-verification.xyz/account-update",
                "expected": "Malicious",
                "description": "Typosquatted domain ('paypa1') on high-abuse .xyz TLD with credential keywords."
            },
            {
                "label": "Malicious - Raw IP Credential Harvester",
                "url": "http://192.168.1.100/paypal/login.php?cmd=_login-run",
                "expected": "Malicious",
                "description": "Raw IP address directly hosting a fake PayPal login portal over HTTP."
            },
            {
                "label": "Malicious - Microsoft Subdomain Cloaking",
                "url": "http://login.microsoftonline.com.account-verification-alert.top/signin",
                "expected": "Malicious",
                "description": "Subdomain stacking spoofing Microsoft Online on an untrusted .top TLD."
            }
        ],
        "emails": [
            {
                "label": "Legitimate - Team Sprint Agenda",
                "subject": "Sprint Planning Agenda for Thursday",
                "sender": "team-lead@techcorp.internal",
                "body": "Hi Team,\n\nPlease find the sprint planning agenda attached for this Thursday at 10 AM. We will review Jira tickets for the upcoming release, discuss deployment blockers, and allocate story points.\n\nBest regards,\nAlex Mercer\nEngineering Lead",
                "expected": "Safe",
                "description": "Internal engineering communication with normal tone, no urgency or suspicious links."
            },
            {
                "label": "Malicious - PayPal Urgent Suspension",
                "subject": "URGENT: Your PayPal Account Has Been Suspended!",
                "sender": "service-security-alert@gmail.com",
                "body": "Dear Valued Customer,\n\nWe detected unauthorized access to your PayPal account from an unknown IP address in Moscow, Russia. Your account has been temporarily LOCKED. You must verify your identity immediately within 24 hours or your balance will be permanently confiscated.\n\nClick the link below to verify your password and credit card number:\nhttp://paypa1-security-verification.xyz/account-update\n\nFailure to take immediate action will result in permanent account termination.\n\nPayPal Security Dept.",
                "expected": "Malicious",
                "description": "Sender spoofing (PayPal sent from @gmail.com), severe urgency, credential theft, malicious link."
            },
            {
                "label": "Malicious - Executive CEO Wire Transfer (Whaling)",
                "subject": "CONFIDENTIAL WIRE TRANSFER REQUEST",
                "sender": "ceo-office@company-exec-spoof.xyz",
                "body": "Are you currently at your desk? I am in an urgent closed-door acquisition meeting and need an emergency wire transfer of $48,500 executed to an escrow account before 2:00 PM today. Do not call my phone as I cannot take calls right now. Send the bank confirmation directly to this email address.",
                "expected": "Malicious",
                "description": "Business Email Compromise (BEC) with spoofed executive sender, strict urgency, wire request."
            },
            {
                "label": "Malicious - Office 365 Password Expiry",
                "subject": "Action Required: Office 365 Password Expiration Notice",
                "sender": "helpdesk-admin@temp-mail.org",
                "body": "FINAL NOTICE: Your Microsoft 365 work password will expire in 1 hour!\n\nTo keep your current password and avoid losing email access, you must validate your credentials now at our portal:\nhttp://office365-urgent-password-reset.icu/login.aspx?user=target\n\nDo not ignore this warning.",
                "expected": "Malicious",
                "description": "Short time limit countdown, disposable sender domain, embedded malicious phishing link."
            }
        ]
    }

# Mount React production build if available
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIST = os.path.abspath(os.path.join(CURRENT_DIR, "..", "..", "frontend", "dist"))

if os.path.exists(FRONTEND_DIST):
    assets_dir = os.path.join(FRONTEND_DIST, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}")
    def serve_spa(full_path: str):
        # Don't intercept API routes
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="API route not found")
        file_path = os.path.join(FRONTEND_DIST, full_path)
        if full_path and os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        index_file = os.path.join(FRONTEND_DIST, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "Frontend build not found. Run 'npm run build' in frontend directory."}

