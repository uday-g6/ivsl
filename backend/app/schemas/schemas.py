from typing import Optional, List, Any, Dict
from pydantic import BaseModel

class UploadResponse(BaseModel):
    scan_id: str
    filename: str
    sha256: str
    size_bytes: int

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: int
    stage: str
    error: Optional[str] = None
    score: Optional[float] = None

class FindingOut(BaseModel):
    id: str
    rule_id: str
    analyzer: str
    category: str
    severity: str
    confidence: str
    title: str
    description: Optional[str]
    file_path: Optional[str]
    line: Optional[int]
    evidence: Optional[str]
    impact: Optional[str]
    remediation: Optional[str]
    cwe: Optional[str]
    status: str
    notes: Optional[str]
    class Config:
        from_attributes = True

class FindingUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
