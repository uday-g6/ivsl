from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database.db import get_db
from ..database.models import Device
from ..core.device_engine import (
    boot_device,
    shutdown_device,
    restart_device
)
from ..core.ios_versions import IOS_VERSIONS
from ..core.settings_engine import DEFAULT_SETTINGS

router = APIRouter(prefix="/api", tags=["Device Engine"])

def find_device(device_id, db):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device

@router.get("/ios-versions")
def list_ios_versions():
    return list(IOS_VERSIONS.values())

@router.post("/devices/{device_id}/boot")
def boot(device_id: str, db: Session = Depends(get_db)):
    device = find_device(device_id, db)
    if device.status == "running":
        return {"message": "Device already running", "device": device}
    result = boot_device(db, device)
    return {"message": "Virtual device booted", "device": result}

@router.post("/devices/{device_id}/shutdown")
def shutdown(device_id: str, db: Session = Depends(get_db)):
    device = find_device(device_id, db)
    result = shutdown_device(db, device)
    return {"message": "Virtual device stopped", "device": result}

@router.post("/devices/{device_id}/restart")
def restart(device_id: str, db: Session = Depends(get_db)):
    device = find_device(device_id, db)
    result = restart_device(db, device)
    return {"message": "Virtual device restarted", "device": result}

@router.get("/devices/{device_id}/settings")
def get_settings(device_id: str, db: Session = Depends(get_db)):
    import copy

    device = find_device(device_id, db)

    if not device.settings:
        device.settings = copy.deepcopy(DEFAULT_SETTINGS)
        db.commit()
        db.refresh(device)

    return device.settings

@router.put("/devices/{device_id}/settings")
def update_settings(
    device_id: str,
    settings: dict,
    db: Session = Depends(get_db)
):
    device = find_device(device_id, db)

    if not isinstance(settings, dict):
        raise HTTPException(400, "Settings must be an object")

    current = device.settings or {}

    def merge(old, new):
        result = dict(old)
        for key, value in new.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = merge(result[key], value)
            else:
                result[key] = value
        return result

    device.settings = merge(current, settings)
    db.commit()
    db.refresh(device)
    return device.settings
