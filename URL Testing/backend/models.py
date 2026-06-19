import datetime
import json
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float
from sqlalchemy.orm import relationship
from backend.database import Base

class ScanHistory(Base):
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(1024), nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(50), nullable=False)  # safe, suspicious, dangerous
    ml_score = Column(Integer, nullable=False)
    rep_score = Column(Integer, nullable=False)
    heuristics_score = Column(Integer, nullable=False)
    _explanations = Column("explanations", Text, default="[]")  # stored as JSON array string
    country = Column(String(100), default="Unknown")
    latitude = Column(Float, default=0.0)
    longitude = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    threats = relationship("ThreatLog", back_populates="scan", cascade="all, delete-orphan")

    @property
    def explanations(self):
        try:
            return json.loads(self._explanations)
        except Exception:
            return []

    @explanations.setter
    def explanations(self, val):
        self._explanations = json.dumps(val)

class ThreatLog(Base):
    __tablename__ = "threat_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_history.id"), nullable=False)
    threat_type = Column(String(100), nullable=False)  # e.g., "Shortened URL", "No HTTPS"
    severity = Column(String(50), nullable=False)     # low, medium, high
    description = Column(String(512), nullable=False)
    
    # Relationship back to scan
    scan = relationship("ScanHistory", back_populates="threats")

class Whitelist(Base):
    __tablename__ = "whitelist"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class Blacklist(Base):
    __tablename__ = "blacklist"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class CommunityReport(Base):
    __tablename__ = "community_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(1024), nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    description = Column(String(512), nullable=False)
    flags_count = Column(Integer, default=1)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

