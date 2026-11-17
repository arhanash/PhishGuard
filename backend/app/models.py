import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Text, DateTime
from .database import Base

class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_type = Column(String(20), nullable=False, index=True) # "url" or "email"
    target = Column(Text, nullable=False) # The URL or Email Subject/Preview
    risk_score = Column(Float, nullable=False) # 0.0 to 100.0
    classification = Column(String(20), nullable=False, index=True) # "Safe", "Suspicious", "Malicious"
    threat_summary = Column(Text, nullable=False)
    
    # JSON strings
    threat_indicators = Column(Text, default="[]")
    detailed_analysis = Column(Text, default="{}")
    security_recommendations = Column(Text, default="[]")
    raw_input = Column(Text, nullable=True) # Full content / body
    
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        try:
            indicators = json.loads(self.threat_indicators) if self.threat_indicators else []
        except Exception:
            indicators = []

        try:
            analysis = json.loads(self.detailed_analysis) if self.detailed_analysis else {}
        except Exception:
            analysis = {}

        try:
            recommendations = json.loads(self.security_recommendations) if self.security_recommendations else []
        except Exception:
            recommendations = []

        return {
            "id": self.id,
            "scan_type": self.scan_type,
            "target": self.target,
            "risk_score": round(self.risk_score, 1),
            "classification": self.classification,
            "threat_summary": self.threat_summary,
            "threat_indicators": indicators,
            "detailed_analysis": analysis,
            "security_recommendations": recommendations,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }

