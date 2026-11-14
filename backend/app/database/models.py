import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship
from app.database.db import Base

def _uuid():
    return str(uuid.uuid4())


# ============================================================
# IVSL MODELS (Device Simulation)
# ============================================================

class Device(Base):
    __tablename__ = "devices"
    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    model = Column(String, default="iPhone 15 Pro")
    hardware_identifier = Column(String, default="iPhone16,1")
    ios_version = Column(String, default="iOS 17")
    ram_gb = Column(Integer, default=8)
    storage_gb = Column(Integer, default=256)
    screen_width = Column(Integer, default=1179)
    screen_height = Column(Integer, default=2556)
    build_profile = Column(String, default="Simulated")
    battery_percent = Column(Integer, default=100)
    status = Column(String, default="ready")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    settings = relationship("DeviceSetting", back_populates="device", cascade="all, delete-orphan")


class DeviceSetting(Base):
    __tablename__ = "device_settings"
    id = Column(String, primary_key=True, default=_uuid)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    category = Column(String, index=True)
    key = Column(String, index=True)
    value = Column(JSON)
    device = relationship("Device", back_populates="settings")


class FileEntry(Base):
    __tablename__ = "files"
    id = Column(String, primary_key=True, default=_uuid)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    path = Column(String, index=True)
    is_dir = Column(Boolean, default=False)
    size_bytes = Column(Integer, default=0)
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class InstalledApp(Base):
    __tablename__ = "installed_apps"
    id = Column(String, primary_key=True, default=_uuid)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    bundle_id = Column(String, index=True)
    display_name = Column(String)
    version = Column(String)
    short_version = Column(String)
    executable = Column(String)
    min_os = Column(String)
    icon_path = Column(String)
    ipa_path = Column(String)
    info_plist = Column(JSON)
    entitlements = Column(JSON)
    install_status = Column(String, default="installed")
    installed_at = Column(DateTime, default=datetime.utcnow)


# ============================================================
# IPA SENTINEL MODELS (Static Analysis)
# ============================================================

class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True, default=_uuid)
    device_id = Column(String, ForeignKey("devices.id", ondelete="CASCADE"), index=True, nullable=True)
    filename = Column(String, nullable=False)
    sha256 = Column(String, index=True)
    size_bytes = Column(Integer, default=0)
    status = Column(String, default="uploaded")
    progress = Column(Integer, default=0)
    stage = Column(String, default="")
    error = Column(Text)
    score = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)

    application = relationship("Application", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    artifacts = relationship("Artifact", back_populates="scan", cascade="all, delete-orphan")


class Application(Base):
    __tablename__ = "applications"
    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    bundle_id = Column(String, index=True)
    name = Column(String)
    display_name = Column(String)
    executable = Column(String)
    version = Column(String)
    short_version = Column(String)
    min_os = Column(String)
    platform = Column(String)
    info_plist = Column(JSON)
    ats = Column(JSON)
    url_schemes = Column(JSON)
    background_modes = Column(JSON)
    usage_descriptions = Column(JSON)
    scan = relationship("Scan", back_populates="application")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    rule_id = Column(String, index=True)
    analyzer = Column(String, index=True)
    category = Column(String)
    severity = Column(String)
    confidence = Column(String)
    title = Column(String)
    description = Column(Text)
    file_path = Column(String)
    line = Column(Integer)
    evidence = Column(Text)
    impact = Column(Text)
    remediation = Column(Text)
    cwe = Column(String)
    status = Column(String, default="open")
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    scan = relationship("Scan", back_populates="findings")


class Artifact(Base):
    __tablename__ = "artifacts"
    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    kind = Column(String, index=True)
    data = Column(JSON)
    scan = relationship("Scan", back_populates="artifacts")


class ScanEvent(Base):
    __tablename__ = "scan_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, index=True)
    ts = Column(DateTime, default=datetime.utcnow)
    message = Column(String)
    level = Column(String, default="info")
