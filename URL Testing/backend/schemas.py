from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class ScanRequest(BaseModel):
    url: str = Field(..., example="https://paypal-security-login-update.xyz")
    html_content: Optional[str] = Field("", example="<html><input type='password'></html>")

class ThreatDetail(BaseModel):
    threat_type: str
    severity: str
    description: str
    
    class Config:
        from_attributes = True

class ScanResponse(BaseModel):
    id: int
    url: str
    domain: str
    risk_score: int
    risk_level: str
    ml_score: int
    rep_score: int
    heuristics_score: int
    explanations: List[str]
    country: str
    latitude: float
    longitude: float
    timestamp: datetime
    threats: List[ThreatDetail] = []
    
    class Config:
        from_attributes = True

class BreachDetail(BaseModel):
    name: str
    domain: str
    breach_date: str
    leaked_data: List[str]
    severity: str

class BreachCheckResponse(BaseModel):
    email: str
    is_compromised: bool
    breaches_count: int
    breaches: List[BreachDetail]
    accuracy_rate: float


class TrendPoint(BaseModel):
    date: str
    scan_count: int
    blocked_count: int

class StatResponse(BaseModel):
    total_scans: int
    average_risk: float
    blocked_count: int
    suspicious_count: int
    safe_count: int
    risk_distribution: Dict[str, int]
    most_common_threats: List[Dict[str, Any]]
    trends: List[TrendPoint]

class WhitelistRequest(BaseModel):
    domain: str = Field(..., example="google.com")

class WhitelistResponse(BaseModel):
    id: int
    domain: str
    timestamp: datetime
    
    class Config:
        from_attributes = True

class BlacklistRequest(BaseModel):
    domain: str = Field(..., example="evil-domain.com")

class BlacklistResponse(BaseModel):
    id: int
    domain: str
    timestamp: datetime
    
    class Config:
        from_attributes = True

class CommunityReportRequest(BaseModel):
    url: str = Field(..., example="https://phishing-site.xyz/login")
    description: str = Field(..., example="Looks like a Chase bank phishing page")

class CommunityReportResponse(BaseModel):
    id: int
    url: str
    domain: str
    description: str
    flags_count: int
    timestamp: datetime
    
    class Config:
        from_attributes = True

class DiagnosticsResponse(BaseModel):
    domain: str
    ssl_valid: bool
    ssl_issuer: str
    ssl_expiry: str
    location: str
    isp: str
    domain_age_days: int
    domain_created: str
    grade: str
    risk_score: int

class TypoSquatItem(BaseModel):
    variant: str
    type: str
    is_online: bool
    ip: str

