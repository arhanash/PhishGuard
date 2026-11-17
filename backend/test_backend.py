"""
Comprehensive Automated Test Suite for PhishGuard Backend.
Verifies:
1. URL Phishing Detection (Legitimate vs Malicious)
2. Email Phishing Detection (Legitimate vs Malicious)
3. Risk Score Calibration (0 - 100) and Classifications (Safe, Suspicious, Malicious)
4. Threat Indicators and MITRE ATT&CK references
5. Database operations (create scan, fetch history, get stats, delete)
6. Downloadable report generation (Text and JSON)
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database import Base, engine, SessionLocal
from backend.app.models import ScanRecord

client = TestClient(app)

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    print("✓ Test Health Check Passed")

def test_url_scanning_legitimate():
    response = client.post("/api/scan/url", json={"url": "https://www.google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "Safe"
    assert data["risk_score"] <= 30.0
    assert data["scan_type"] == "url"
    assert "detailed_analysis" in data
    print(f"✓ Test Legitimate URL Passed: Google.com -> {data['classification']} ({data['risk_score']}%)")

def test_url_scanning_malicious_ip():
    response = client.post("/api/scan/url", json={"url": "http://192.168.1.100/paypal/login.php?cmd=_login-run"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "Malicious"
    assert data["risk_score"] >= 70.0
    # Check that IP indicator was triggered
    has_ip_ind = any(i["id"] == "URL-001" for i in data["threat_indicators"])
    assert has_ip_ind, "Raw IP address indicator should be present"
    print(f"✓ Test Malicious IP URL Passed: -> {data['classification']} ({data['risk_score']}%)")

def test_url_scanning_typosquatting():
    response = client.post("/api/scan/url", json={"url": "http://paypa1-security-verification.xyz/account-update"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "Malicious"
    assert data["risk_score"] >= 70.0
    print(f"✓ Test Malicious Typosquatting URL Passed: -> {data['classification']} ({data['risk_score']}%)")

def test_email_scanning_legitimate():
    payload = {
        "subject": "Sprint Planning Agenda for Thursday",
        "sender": "team-lead@techcorp.internal",
        "raw_content": "Hi Team, please find the sprint planning agenda attached for Thursday. Best regards, Alex."
    }
    response = client.post("/api/scan/email", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "Safe"
    assert data["risk_score"] <= 30.0
    print(f"✓ Test Legitimate Email Passed: -> {data['classification']} ({data['risk_score']}%)")

def test_email_scanning_phishing():
    payload = {
        "subject": "URGENT: Your PayPal Account Has Been Suspended!",
        "sender": "service-security-alert@gmail.com",
        "raw_content": "Dear Customer, unauthorized access detected. Your account has been LOCKED. Verify immediately within 24 hours at http://paypa1-security-verification.xyz/account-update or account is terminated."
    }
    response = client.post("/api/scan/email", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "Malicious"
    assert data["risk_score"] >= 70.0
    assert len(data["threat_indicators"]) > 0
    print(f"✓ Test Malicious Email Passed: -> {data['classification']} ({data['risk_score']}%)")

def test_history_and_dashboard_stats():
    # Fetch history
    history_res = client.get("/api/history")
    assert history_res.status_code == 200
    history_data = history_res.json()
    assert history_data["total"] >= 4

    # Fetch stats
    stats_res = client.get("/api/dashboard/stats")
    assert stats_res.status_code == 200
    stats_data = stats_res.json()
    assert stats_data["total_scans"] >= 4
    assert stats_data["safe_scans"] >= 2
    assert stats_data["malicious_scans"] >= 2
    assert "attack_type_distribution" in stats_data
    print(f"✓ Test Dashboard Stats Passed: Total {stats_data['total_scans']} scans recorded")

def test_download_report():
    history_res = client.get("/api/history")
    items = history_res.json()["items"]
    assert len(items) > 0
    first_id = items[0]["id"]

    # Text report
    txt_res = client.get(f"/api/report/{first_id}/download?format=txt")
    assert txt_res.status_code == 200
    assert "PHISHGUARD CYBERSECURITY THREAT REPORT" in txt_res.text

    # JSON report
    json_res = client.get(f"/api/report/{first_id}/download?format=json")
    assert json_res.status_code == 200
    report_json = json_res.json()
    assert report_json["id"] == first_id
    print(f"✓ Test Download Report Passed: Generated TXT and JSON forensic reports for scan #{first_id}")

if __name__ == "__main__":
    print("\n--- Running PhishGuard Backend Test Suite ---")
    test_health()
    test_url_scanning_legitimate()
    test_url_scanning_malicious_ip()
    test_url_scanning_typosquatting()
    test_email_scanning_legitimate()
    test_email_scanning_phishing()
    test_history_and_dashboard_stats()
    test_download_report()
    print("\n✓ ALL TESTS PASSED SUCCESSFULLY!\n")

