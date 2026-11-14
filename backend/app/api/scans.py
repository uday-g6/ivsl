import re
import uuid
from pathlib import Path
from pydantic import BaseModel
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database.db import get_db
from app.database.models import Scan, Finding, Application, Artifact
from app.core.security import sha256_file, validate_ipa
from app.core.orchestrator import start_scan_async, request_cancel
from app.schemas.schemas import UploadResponse, ScanStatus, FindingOut, FindingUpdate
from app.scoring.risk_engine import compute_score
from app.analyzers.ios.base import RawFinding
from app.reporting.pdf import build_pdf

router = APIRouter()

MAX = settings.MAX_UPLOAD_MB * 1024 * 1024


@router.post("/scans/upload", response_model=UploadResponse)
async def upload(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.lower().endswith(".ipa"):
        raise HTTPException(400, "Only .ipa files allowed")
    scan_id = str(uuid.uuid4())
    dst = settings.UPLOAD_DIR / f"{scan_id}.ipa"
    size = 0
    with open(dst, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX:
                out.close()
                dst.unlink(missing_ok=True)
                raise HTTPException(413, "Upload exceeds size limit")
            out.write(chunk)
    try:
        validate_ipa(dst)
    except Exception as e:
        dst.unlink(missing_ok=True)
        raise HTTPException(400, f"Invalid IPA: {e}")
    digest = sha256_file(dst)

    scan = Scan(id=scan_id, filename=file.filename, sha256=digest, size_bytes=size, status="uploaded")
    db.add(scan)
    db.commit()
    return UploadResponse(scan_id=scan_id, filename=file.filename, sha256=digest, size_bytes=size)


@router.post("/scans/{scan_id}/start", response_model=ScanStatus)
def start(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status == "scanning":
        raise HTTPException(409, "Already scanning")
    ipa = settings.UPLOAD_DIR / f"{scan_id}.ipa"
    if not ipa.exists():
        raise HTTPException(404, "IPA file missing")
    scan.status = "scanning"
    scan.progress = 1
    scan.stage = "Queued"
    db.commit()
    start_scan_async(scan_id, ipa)
    return ScanStatus(scan_id=scan_id, status=scan.status, progress=1, stage="Queued")


@router.post("/scans/{scan_id}/cancel")
def cancel(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404)
    request_cancel(scan_id)
    return {"ok": True}


@router.get("/scans")
def list_scans(db: Session = Depends(get_db)):
    items = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return [{"id": s.id, "filename": s.filename, "status": s.status,
             "score": s.score,
             "created_at": s.created_at.isoformat() if s.created_at else None,
             "sha256": s.sha256, "findings_count": db.query(Finding).filter_by(scan_id=s.id).count()} for s in items]


@router.get("/scans/{scan_id}", response_model=ScanStatus)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404)
    return ScanStatus(scan_id=scan.id, status=scan.status, progress=scan.progress,
                      stage=scan.stage, error=scan.error, score=scan.score)


@router.get("/scans/{scan_id}/progress")
def progress(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404)
    return {"status": scan.status, "progress": scan.progress, "stage": scan.stage, "error": scan.error}


@router.get("/scans/{scan_id}/application")
def get_app(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404)
    app = db.query(Application).filter_by(scan_id=scan_id).first()
    
    result = {
        # File-level info
        "filename": scan.filename,
        "sha256": scan.sha256,
        "size_bytes": scan.size_bytes,
        "scan_date": scan.created_at.isoformat() if scan.created_at else None,
        "score": scan.score,
        "status": scan.status,
    }
    
    if app:
        # Parse platform from string like "['iPhoneOS']"
        platform_str = app.platform or ""
        platforms = re.findall(r"'([^']+)'", platform_str) or []
        
        # Extract more from info_plist
        plist = app.info_plist or {}
        
        result.update({
            "bundle_id": app.bundle_id,
            "name": app.name,
            "display_name": app.display_name,
            "executable": app.executable,
            "version": app.version,
            "short_version": app.short_version,
            "build": app.version,
            "min_os": app.min_os,
            "platforms": platforms,
            "device_family": plist.get("UIDeviceFamily", []),
            "supported_orientations": plist.get("UISupportedInterfaceOrientations", []),
            "url_schemes": plist.get("CFBundleURLTypes", []),
            "background_modes": app.background_modes or [],
            "usage_descriptions": app.usage_descriptions or {},
            "info_plist": plist,
        })
    
    return result


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def get_findings(scan_id: str, severity: str = None, db: Session = Depends(get_db)):
    q = db.query(Finding).filter_by(scan_id=scan_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    return q.order_by(Finding.severity).all()


@router.get("/scans/{scan_id}/secrets")
def get_secrets(scan_id: str, db: Session = Depends(get_db)):
    items = db.query(Finding).filter_by(scan_id=scan_id, analyzer="secrets").all()
    return [FindingOut.model_validate(f) for f in items]


@router.get("/scans/{scan_id}/entitlements")
def get_entitlements(scan_id: str, db: Session = Depends(get_db)):
    a = db.query(Artifact).filter_by(scan_id=scan_id, kind="entitlements").first()
    return a.data if a else {}


@router.get("/scans/{scan_id}/privacy")
def get_privacy(scan_id: str, db: Session = Depends(get_db)):
    a = db.query(Artifact).filter_by(scan_id=scan_id, kind="privacy").first()
    return a.data if a else {}


@router.get("/scans/{scan_id}/frameworks")
def get_frameworks(scan_id: str, db: Session = Depends(get_db)):
    a = db.query(Artifact).filter_by(scan_id=scan_id, kind="frameworks").first()
    return a.data if a else {}


@router.get("/scans/{scan_id}/signature")
def get_signature(scan_id: str, db: Session = Depends(get_db)):
    a = db.query(Artifact).filter_by(scan_id=scan_id, kind="signature").first()
    return a.data if a else {}


@router.get("/scans/{scan_id}/recommendations")
def get_recommendations(scan_id: str, db: Session = Depends(get_db)):
    items = db.query(Finding).filter_by(scan_id=scan_id).all()
    return [{"rule_id": f.rule_id, "title": f.title, "remediation": f.remediation}
            for f in items if f.remediation]


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def patch_finding(finding_id: str, upd: FindingUpdate, db: Session = Depends(get_db)):
    f = db.query(Finding).get(finding_id)
    if not f:
        raise HTTPException(404)
    if upd.status is not None:
        f.status = upd.status
    if upd.notes is not None:
        f.notes = upd.notes
    db.commit()
    db.refresh(f)
    return f





@router.get("/scans/{scan_id}/file")
def get_file_content(scan_id: str, path: str):
    import os, re
    from app.config import settings

    base = settings.EXTRACT_DIR / scan_id / "Payload"
    if not base.exists():
        raise HTTPException(404, "Extracted files not found")
    app_dirs = [d for d in base.iterdir() if d.is_dir() and d.suffix == ".app"]
    if not app_dirs:
        raise HTTPException(404, "No .app bundle found")

    target = app_dirs[0] / path
    if not str(target.resolve()).startswith(str(app_dirs[0].resolve())):
        raise HTTPException(400, "Invalid path")
    if not target.exists():
        raise HTTPException(404, "File not found")

    size = target.stat().st_size
    if size > 5 * 1024 * 1024:
        return {"type": "too_large", "size": size}

    raw = target.read_bytes()
    # Detect binary (any null byte in first 4KB)
    is_binary = b"\x00" in raw[:4096]

    if not is_binary:
        try:
            return {
                "type": "text",
                "size": size,
                "content": raw.decode("utf-8", errors="replace"),
            }
        except Exception:
            is_binary = True

    # Binary: extract ASCII strings
    strings = [m.group(0).decode("ascii", errors="replace") for m in re.finditer(b"[\\x20-\\x7E]{6,}", raw)]
    hex_preview = " ".join(f"{b:02x}" for b in raw[:256])

    return {
        "type": "binary",
        "size": size,
        "hex_preview": hex_preview,
        "strings_count": len(strings),
        "strings": strings[:500],
    }


@router.get("/scans/{scan_id}/download")
def download_file(scan_id: str, path: str):
    from app.config import settings
    from fastapi.responses import FileResponse

    base = settings.EXTRACT_DIR / scan_id / "Payload"
    if not base.exists():
        raise HTTPException(404, "Extracted files not found")
    app_dirs = [d for d in base.iterdir() if d.is_dir() and d.suffix == ".app"]
    if not app_dirs:
        raise HTTPException(404, "No .app bundle found")

    target = app_dirs[0] / path
    if not str(target.resolve()).startswith(str(app_dirs[0].resolve())):
        raise HTTPException(400, "Invalid path")
    if not target.exists():
        raise HTTPException(404, "File not found")
    return FileResponse(str(target), filename=target.name, media_type="application/octet-stream")




@router.get("/scans/{scan_id}/search")
def search_in_scan(scan_id: str, q: str, db: Session = Depends(get_db)):
    from app.config import settings
    import os

    results = []
    query_lower = q.lower().strip()
    if not query_lower:
        return {"query": q, "count": 0, "results": []}

    # 1. Search the validated Findings Database (Highest Confidence)
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    for f in findings:
        if query_lower in (f.title or "").lower() or \
           query_lower in (f.evidence or "").lower() or \
           query_lower in (f.file_path or "").lower():
            results.append({
                "type": "validated_finding",
                "file": f.file_path or "N/A",
                "line": f.line or 1,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence,
                "context": "Verified by IPA Sentinel Analyzer"
            })

    # 2. Search ONLY plain text files (No DLLs, No binaries)
    base = settings.EXTRACT_DIR / scan_id / "Payload"
    if base.exists():
        app_dirs = [d for d in base.iterdir() if d.is_dir() and d.suffix == ".app"]
        if app_dirs:
            app_root = app_dirs[0]
            # STRICT WHITELIST of text formats
            allowed_exts = ('.plist', '.json', '.xml', '.txt', '.strings', '.cs', '.config', '.js', '.html', '.css')
            
            for root, dirs, files in os.walk(app_root):
                for file in files:
                    if not file.endswith(allowed_exts):
                        continue
                        
                    path = Path(root) / file
                    if path.stat().st_size > 5 * 1024 * 1024:
                        continue
                        
                    try:
                        raw = path.read_bytes()
                        # Reject binary files entirely
                        if b"\x00" in raw[:4096]:
                            continue
                            
                        text = raw.decode("utf-8", errors="ignore")
                        lines = text.splitlines()
                        
                        for i, line in enumerate(lines):
                            if query_lower in line.lower():
                                if len(line.strip()) < 4:
                                    continue
                                    
                                # Get context (previous and next line)
                                context_lines = []
                                if i > 0: context_lines.append(lines[i-1].strip()[:80])
                                context_lines.append(">>> " + line.strip()[:100])
                                if i < len(lines) - 1: context_lines.append(lines[i+1].strip()[:80])
                                
                                rel_path = str(path.relative_to(app_root))
                                
                                already = any(r.get("file") == rel_path and r.get("line") == i + 1 for r in results)
                                if not already:
                                    results.append({
                                        "type": "code_match",
                                        "file": rel_path,
                                        "line": i + 1,
                                        "title": f"Match in {file}",
                                        "evidence": line.strip()[:200],
                                        "context": "\n".join(context_lines)
                                    })
                    except Exception:
                        pass

    return {"query": q, "count": len(results), "results": results[:50]}



class CompareRequest(BaseModel):
    scan_id_a: str
    scan_id_b: str


@router.post("/scans/compare")
def compare_scans(req: CompareRequest, db: Session = Depends(get_db)):
    from app.schemas.schemas import FindingOut

    a = db.query(Scan).get(req.scan_id_a)
    b = db.query(Scan).get(req.scan_id_b)
    if not a or not b:
        raise HTTPException(404, "One or both scans not found")

    fa = db.query(Finding).filter_by(scan_id=req.scan_id_a).all()
    fb = db.query(Finding).filter_by(scan_id=req.scan_id_b).all()

    def fingerprint(f):
        return (f.rule_id or "", f.file_path or "", f.evidence or "")

    set_a = {fingerprint(f) for f in fa}
    set_b = {fingerprint(f) for f in fb}

    new_findings = [f for f in fb if fingerprint(f) not in set_a]
    fixed_findings = [f for f in fa if fingerprint(f) not in set_b]
    persistent_findings = [f for f in fb if fingerprint(f) in set_a]

    score_delta = (b.score or 0) - (a.score or 0)

    return {
        "scan_a": {"id": a.id, "filename": a.filename, "score": a.score, "findings": len(fa)},
        "scan_b": {"id": b.id, "filename": b.filename, "score": b.score, "findings": len(fb)},
        "score_delta": round(score_delta, 1),
        "improvement": score_delta > 0,
        "new_findings": [FindingOut.model_validate(f).model_dump() for f in new_findings],
        "fixed_findings": [FindingOut.model_validate(f).model_dump() for f in fixed_findings],
        "persistent_findings": [FindingOut.model_validate(f).model_dump() for f in persistent_findings],
        "summary": {
            "new_count": len(new_findings),
            "fixed_count": len(fixed_findings),
            "persistent_count": len(persistent_findings),
        },
    }

@router.get("/scans/{scan_id}/binary")
def get_binary(scan_id: str, db: Session = Depends(get_db)):
    """Merge all binary-related artifacts into a single response."""
    kinds = [
        "macho", "filesystem", "framework_version", "cve", "yara", "strings",
        "code", "secrets",
        # New analyzers
        "url_schemes", "permissions", "info_disclosure", "webview", "remote_access",
        "symbols", "local_data", "debug_artifacts",
        "app_info", "ipa_package", "ats", "signature", "entitlements",
        "privacy", "frameworks",
    ]
    result = {}
    for kind in kinds:
        artifact = db.query(Artifact).filter_by(scan_id=scan_id, kind=kind).first()
        if artifact and artifact.data:
            result[kind] = artifact.data
    return result



@router.get("/scans/{scan_id}/icon")
def get_app_icon(scan_id: str, db: Session = Depends(get_db)):
    """Extract and serve the app icon from the extracted IPA."""
    from app.config import settings
    from fastapi.responses import FileResponse
    import plistlib

    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404)

    app = db.query(Application).filter_by(scan_id=scan_id).first()
    base = settings.EXTRACT_DIR / scan_id / "Payload"

    if not base.exists():
        raise HTTPException(404, "Extracted files not found")

    app_dirs = [d for d in base.iterdir() if d.is_dir() and d.suffix == ".app"]
    if not app_dirs:
        raise HTTPException(404, "No .app bundle found")

    app_root = app_dirs[0]
    icon_candidates = []

    # Method 1: Read from Info.plist
    plist_path = app_root / "Info.plist"
    if plist_path.exists():
        try:
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)

            # Try CFBundleIcons
            icons = plist.get("CFBundleIcons", {})
            primary = icons.get("CFBundlePrimaryIcon", {})
            files = primary.get("CFBundleIconFiles", [])

            # Try CFBundleIcons~ipad
            icons_ipad = plist.get("CFBundleIcons~ipad", {})
            primary_ipad = icons_ipad.get("CFBundlePrimaryIcon", {})
            files += primary_ipad.get("CFBundleIconFiles", [])

            for name in files:
                # Try both name.png and name@2x.png
                for suffix in ["", "@2x.png", "@3x.png", ".png"]:
                    candidate = app_root / f"{name}{suffix}"
                    if candidate.exists():
                        icon_candidates.append(candidate)

            # Also try CFBundleIconFiles (older key)
            for name in plist.get("CFBundleIconFiles", []):
                for suffix in ["", "@2x.png", "@3x.png", ".png"]:
                    candidate = app_root / f"{name}{suffix}"
                    if candidate.exists():
                        icon_candidates.append(candidate)
        except Exception:
            pass

    # Method 2: Scan for AppIcon* / Icon-* files
    for pattern in ["AppIcon*.png", "Icon-*.png", "icon*.png", "*.appiconset/*.png"]:
        for f in app_root.rglob(pattern):
            icon_candidates.append(f)

    # Deduplicate and sort by size (largest first)
    seen = set()
    unique = []
    for c in icon_candidates:
        try:
            key = str(c.resolve())
            if key not in seen and c.stat().st_size > 100:
                seen.add(key)
                unique.append(c)
        except Exception:
            pass

    if not unique:
        raise HTTPException(404, "No icon found in app bundle")

    # Sort by file size (largest = highest resolution typically)
    unique.sort(key=lambda x: x.stat().st_size, reverse=True)
    best_icon = unique[0]

    return FileResponse(str(best_icon), media_type="image/png")


@router.get("/reports/{scan_id}/pdf")
def pdf(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404)
    app = db.query(Application).filter_by(scan_id=scan_id).first()
    findings = db.query(Finding).filter_by(scan_id=scan_id).all()
    raw = [RawFinding(
        rule_id=f.rule_id,
        analyzer=f.analyzer,
        category=f.category or "",
        severity=f.severity,
        confidence=f.confidence,
        title=f.title,
        file_path=f.file_path,
        evidence=f.evidence,   # ← INCLUDE evidence so dedup keeps unique CVEs
    ) for f in findings]
    score_info = compute_score(raw)
    out = settings.REPORT_DIR / f"{scan_id}.pdf"
    build_pdf(out, scan, app, findings, score_info)
    return FileResponse(str(out), media_type="application/pdf", filename=f"ipa-sentinel-{scan_id}.pdf")


@router.get("/reports/{scan_id}/json")
def json_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404)
    app = db.query(Application).filter_by(scan_id=scan_id).first()
    findings = db.query(Finding).filter_by(scan_id=scan_id).all()
    raw = [RawFinding(
        rule_id=f.rule_id,
        analyzer=f.analyzer,
        category=f.category or "",
        severity=f.severity,
        confidence=f.confidence,
        title=f.title,
        file_path=f.file_path,
        evidence=f.evidence,   # ← INCLUDE evidence so dedup keeps unique CVEs
    ) for f in findings]
    data = {
        "scan_id": scan.id, "filename": scan.filename, "sha256": scan.sha256,
        "score": compute_score(raw),
        "application": {"bundle_id": app.bundle_id if app else None,
                        "version": app.short_version if app else None},
        "findings": [FindingOut.model_validate(f).model_dump() for f in findings],
    }
    return JSONResponse(data)


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404)
    db.delete(scan)
    db.commit()
    (settings.UPLOAD_DIR / f"{scan_id}.ipa").unlink(missing_ok=True)
    return {"deleted": True}
