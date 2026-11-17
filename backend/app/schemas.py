from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class URLScanRequest(BaseModel):
    url: str = Field(..., description="Target website URL to scan")

class EmailScanRequest(BaseModel):
    raw_content: str = Field(..., description="Raw email text, or body content")
    subject: Optional[str] = Field(None, description="Optional email subject")
    sender: Optional[str] = Field(None, description="Optional sender header or address")

class ThreatIndicator(BaseModel):
    id: str
    category: str
    name: str
    severity: str # "Low", "Medium", "High", "Critical"
    description: str
    score_impact: float
    mitre_ref: Optional[str] = None

class ScanResultResponse(BaseModel):
    id: Optional[int] = None
    scan_type: str
    target: str
    risk_score: float
    classification: str # "Safe", "Suspicious", "Malicious"
    threat_summary: str
    threat_indicators: List[ThreatIndicator]
    detailed_analysis: Dict[str, Any]
    security_recommendations: List[str]
    timestamp: str

class DashboardStatsResponse(BaseModel):
    total_scans: int
    safe_scans: int
    suspicious_scans: int
    malicious_scans: int
    avg_risk_score: float
    url_scans_count: int
    email_scans_count: int
    recent_scans: List[Dict[str, Any]]
    attack_type_distribution: Dict[str, int]

