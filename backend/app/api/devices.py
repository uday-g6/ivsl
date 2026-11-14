from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional
from ..database.db import get_db
from ..database.models import Device

router = APIRouter(prefix="/api/devices", tags=["Devices"])

class DeviceCreate(BaseModel):
    name: str
    model: str
    hardware_identifier: str
    ios_version: str
    ram_gb: int = Field(default=8, ge=1, le=64)
    storage_gb: int = Field(default=128, ge=16, le=2048)
    screen_width: int = Field(default=393, ge=100, le=5000)
    screen_height: int = Field(default=852, ge=100, le=5000)
    build_profile: Optional[str] = None

@router.post("/")
def create_device(data: DeviceCreate, db: Session = Depends(get_db)):
    device = Device(**data.model_dump())
    db.add(device)
    db.commit()
    db.refresh(device)
    return device

@router.get("/")
def list_devices(db: Session = Depends(get_db)):
    return db.query(Device).all()

@router.get("/{device_id}")
def get_device(device_id: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device

@router.delete("/{device_id}")
def delete_device(device_id: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    db.delete(device)
    db.commit()
    return {"message": "Device deleted"}
