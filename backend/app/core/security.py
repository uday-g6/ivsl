import hashlib
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import List, Tuple
from app.config import settings

class UnsafeArchive(Exception):
    pass

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def validate_ipa(path: Path) -> None:
    if path.suffix.lower() != ".ipa":
        raise UnsafeArchive("File must have .ipa extension")
    if not zipfile.is_zipfile(path):
        raise UnsafeArchive("Not a valid ZIP (IPA) archive")

def safe_extract(ipa_path: Path, dest: Path) -> Tuple[List[str], int]:
    """
    Extract IPA with zip-slip + zip-bomb protections.
    Returns (file_list, total_uncompressed_bytes).
    """
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    max_bytes = settings.MAX_EXTRACTED_MB * 1024 * 1024
    total = 0
    names: List[str] = []

    with zipfile.ZipFile(ipa_path) as zf:
        infos = zf.infolist()
        if len(infos) > settings.MAX_FILES_PER_IPA:
            raise UnsafeArchive(f"Too many entries: {len(infos)}")

        for info in infos:
            total += info.file_size
            if total > max_bytes:
                raise UnsafeArchive("ZIP bomb: extracted size limit exceeded")

            # Path traversal guard
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest) + os.sep) and target != dest:
                raise UnsafeArchive(f"Zip-slip attempt: {info.filename}")
            # Symlink guard
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise UnsafeArchive(f"Symlink in archive: {info.filename}")

            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, length=1024 * 1024)
            names.append(info.filename)

    return names, total

def make_scan_workdir(scan_id: str) -> Path:
    d = settings.EXTRACT_DIR / scan_id
    d.mkdir(parents=True, exist_ok=True)
    return d

def cleanup_workdir(scan_id: str) -> None:
    d = settings.EXTRACT_DIR / scan_id
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)