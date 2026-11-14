from pathlib import Path
from sqlalchemy.orm import Session
from ..database.models import Device

STORAGE_ROOT = Path("storage/devices").resolve()

def device_root(device_id: str) -> Path:
    return STORAGE_ROOT / device_id

def initialize_filesystem(device: Device):
    root = device_root(device.id)

    directories = [
        "Applications",
        "System/Applications",
        "System/Library",
        "var/mobile/Containers/Data/Application",
        "var/mobile/Library",
        "var/mobile/Documents",
        "var/mobile/tmp",
        "Developer",
        "Downloads",
        "Photos"
    ]

    for directory in directories:
        (root / directory).mkdir(parents=True, exist_ok=True)

    return root

def boot_device(db: Session, device: Device):
    initialize_filesystem(device)
    device.status = "running"
    db.commit()
    db.refresh(device)
    return device

def shutdown_device(db: Session, device: Device):
    device.status = "stopped"
    db.commit()
    db.refresh(device)
    return device

def restart_device(db: Session, device: Device):
    device.status = "stopped"
    db.commit()

    initialize_filesystem(device)

    device.status = "running"
    db.commit()
    db.refresh(device)
    return device
