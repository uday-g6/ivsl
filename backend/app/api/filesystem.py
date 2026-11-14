from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from ..database.db import get_db
from ..database.models import Device
from ..core.device_engine import initialize_filesystem, device_root

router = APIRouter(prefix="/api/devices", tags=["Virtual Filesystem"])

class DirectoryCreate(BaseModel):
    path: str

def get_device(device_id, db):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device

def safe_path(device_id, relative_path):
    if "\x00" in relative_path or "\\" in relative_path:
        raise HTTPException(400, "Invalid path")

    requested = Path(relative_path)

    if requested.is_absolute() or ".." in requested.parts:
        raise HTTPException(400, "Path traversal is not allowed")

    root = device_root(device_id).resolve()
    target = (root / requested).resolve()

    if not target.is_relative_to(root):
        raise HTTPException(400, "Invalid filesystem path")

    return target

@router.get("/{device_id}/filesystem")
def list_files(
    device_id: str,
    path: str = "",
    db: Session = Depends(get_db)
):
    device = get_device(device_id, db)
    root = initialize_filesystem(device)
    target = safe_path(device_id, path)

    if not target.exists():
        raise HTTPException(404, "Directory not found")

    if not target.is_dir():
        raise HTTPException(400, "Path is not a directory")

    return {
        "device_id": device_id,
        "path": path,
        "entries": [
            {
                "name": item.name,
                "type": "directory" if item.is_dir() else "file"
            }
            for item in sorted(target.iterdir())
        ]
    }

@router.post("/{device_id}/filesystem/directories")
def create_directory(
    device_id: str,
    data: DirectoryCreate,
    db: Session = Depends(get_db)
):
    device = get_device(device_id, db)
    initialize_filesystem(device)

    target = safe_path(device_id, data.path)

    target.mkdir(parents=True, exist_ok=True)

    return {
        "message": "Directory created",
        "path": data.path
    }
