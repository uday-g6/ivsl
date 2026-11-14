import json
import logging
import threading
from pathlib import Path
from typing import List
from app.database.db import SessionLocal
from app.database.models import Scan, Application, Finding, Artifact, ScanEvent
from app.core.security import safe_extract, make_scan_workdir, cleanup_workdir, validate_ipa
from app.analyzers.ios.base import AnalyzerContext, RawFinding
from app.analyzers.ios.ipa_analyzer import IPAPackageAnalyzer
from app.analyzers.ios.plist_analyzer import AppInfoAnalyzer, load_plist
from app.analyzers.ios.ats_analyzer import ATSAnalyzer
from app.analyzers.ios.secret_analyzer import SecretScannerAnalyzer
from app.analyzers.ios.macho_analyzer import MachOAnalyzer
from app.analyzers.ios.entitlement_analyzer import EntitlementAnalyzer
from app.analyzers.ios.privacy_analyzer import PrivacyManifestAnalyzer
from app.analyzers.ios.framework_analyzer import FrameworkAnalyzer
from app.analyzers.ios.signature_analyzer import SignatureAnalyzer
from app.analyzers.ios.file_system_analyzer import FileSystemAnalyzer
from app.analyzers.ios.framework_version_analyzer import FrameworkVersionAnalyzer
from app.analyzers.ios.cve_analyzer import CVEAnalyzer
from app.analyzers.ios.debug_artifact_analyzer import DebugArtifactAnalyzer
from app.analyzers.ios.local_data_analyzer import LocalDataAnalyzer
from app.analyzers.ios.symbol_analyzer import SymbolAnalyzer
from app.analyzers.ios.webview_analyzer import WebViewAnalyzer
from app.analyzers.ios.info_disclosure_analyzer import InfoDisclosureAnalyzer
from app.analyzers.ios.permission_analyzer import PermissionAnalyzer
from app.analyzers.ios.url_scheme_analyzer import URLSchemeAnalyzer
from app.analyzers.ios.remote_access_analyzer import RemoteAccessAnalyzer
from app.analyzers.ios.strings_analyzer import StringsAnalyzer
from app.analyzers.ios.yara_analyzer import YaraAnalyzer
from app.analyzers.ios.code_analyzer import CodeAnalyzer
from app.scoring.risk_engine import compute_score

log = logging.getLogger("orchestrator")

CANCELLED = {}


def request_cancel(scan_id: str):
    CANCELLED[scan_id] = True


def _set_stage(db, scan, pct, stage):
    scan.progress = pct
    scan.stage = stage
    db.commit()
    db.add(ScanEvent(scan_id=scan.id, message=stage))
    db.commit()


def _discover_app(extracted_root: Path):
    payload = extracted_root / "Payload"
    if not payload.exists():
        return None
    apps = [p for p in payload.iterdir() if p.is_dir() and p.suffix == ".app"]
    return apps[0] if apps else None


def run_scan(scan_id: str, ipa_path: Path):
    db = SessionLocal()
    try:
        scan = db.query(Scan).get(scan_id)
        if not scan:
            return
        scan.status = "scanning"
        db.commit()

        _set_stage(db, scan, 5, "Validating IPA")
        validate_ipa(ipa_path)

        _set_stage(db, scan, 10, "Extracting archive")
        work = make_scan_workdir(scan_id)
        names, total = safe_extract(ipa_path, work)

        _set_stage(db, scan, 20, "Discovering application bundle")
        app_root = _discover_app(work)
        if not app_root:
            raise RuntimeError("Payload/*.app not found")
        info_plist = load_plist(app_root / "Info.plist")
        exe_name = info_plist.get("CFBundleExecutable")
        exe_path = app_root / exe_name if exe_name else None
        all_files = [p for p in work.rglob("*") if p.is_file()]

        existing = db.query(Application).filter_by(scan_id=scan.id).first()
        if not existing:
            app = Application(
                scan_id=scan.id,
                bundle_id=info_plist.get("CFBundleIdentifier"),
                name=info_plist.get("CFBundleName"),
                display_name=info_plist.get("CFBundleDisplayName"),
                executable=exe_name,
                version=info_plist.get("CFBundleVersion"),
                short_version=info_plist.get("CFBundleShortVersionString"),
                min_os=info_plist.get("MinimumOSVersion"),
                platform=str(info_plist.get("CFBundleSupportedPlatforms") or []),
                info_plist=info_plist,
                ats=info_plist.get("NSAppTransportSecurity", {}),
                url_schemes=[t for t in (info_plist.get("CFBundleURLTypes") or [])],
                background_modes=info_plist.get("UIBackgroundModes", []),
                usage_descriptions={k: v for k, v in info_plist.items()
                                    if k.startswith("NS") and k.endswith("UsageDescription")},
            )
            db.add(app)
            db.commit()

        ctx = AnalyzerContext(
            scan_id=scan_id, app_root=app_root, executable_path=exe_path,
            info_plist=info_plist, all_files=all_files,
        )

        analyzers = [
            (IPAPackageAnalyzer(), 30, "IPA package"),
            (AppInfoAnalyzer(), 35, "App info"),
            (ATSAnalyzer(), 45, "ATS"),
            (SignatureAnalyzer(), 50, "Code signature"),
            (EntitlementAnalyzer(), 55, "Entitlements"),
            (PrivacyManifestAnalyzer(), 60, "Privacy manifest"),
            (FrameworkAnalyzer(), 65, "Frameworks"),
            (MachOAnalyzer(), 75, "Mach-O"),
            (SecretScannerAnalyzer(), 88, "Secrets"),
            (FileSystemAnalyzer(), 90, "File Tree"),
            (YaraAnalyzer(), 92, "YARA Engine"),
            (StringsAnalyzer(), 94, "Binary Strings"),
            (CodeAnalyzer(), 96, "Deep Code Scan"),
            (FrameworkVersionAnalyzer(), 97, "Framework Versions"),
            (CVEAnalyzer(), 98, "CVE Matching"),
            (URLSchemeAnalyzer(), 40, "URL Schemes"),
            (RemoteAccessAnalyzer(), 41, "Remote Access"),
            (PermissionAnalyzer(), 42, "Permissions"),
            (WebViewAnalyzer(), 43, "WebView"),
            (SymbolAnalyzer(), 44, "Symbols"),
            (LocalDataAnalyzer(), 85, "Local Data"),
            (InfoDisclosureAnalyzer(), 86, "Info Disclosure"),
            (DebugArtifactAnalyzer(), 87, "Debug Artifacts"),
        ]

        all_findings: List[RawFinding] = []
        for a, pct, stage in analyzers:
            if CANCELLED.get(scan_id):
                scan.status = "cancelled"
                db.commit()
                return
            _set_stage(db, scan, pct, stage)
            try:
                results = a.run(ctx) or []
            except Exception as e:
                log.exception("analyzer failed: %s", a.name)
                db.add(ScanEvent(scan_id=scan_id, message=f"{a.name} failed: {e}", level="error"))
                db.commit()
                results = []
            all_findings.extend(results)

            blob = getattr(a, "result", None)
            if blob is not None:
                try:
                    db.add(Artifact(scan_id=scan_id, kind=a.name, data=_json_safe(blob)))
                    db.commit()
                except Exception:
                    log.exception("artifact save failed: %s", a.name)

        _set_stage(db, scan, 92, "Scoring")
        score_info = compute_score(all_findings)

        _set_stage(db, scan, 96, "Saving findings")
        seen = set()
        for f in all_findings:
            key = (f.rule_id, f.file_path, f.evidence)
            if key in seen:
                continue
            seen.add(key)
            db.add(Finding(
                scan_id=scan_id,
                rule_id=f.rule_id, analyzer=f.analyzer, category=f.category,
                severity=f.severity, confidence=f.confidence,
                title=f.title, description=f.description,
                file_path=f.file_path, line=f.line, evidence=f.evidence,
                impact=f.impact, remediation=f.remediation, cwe=f.cwe,
            ))
        scan.score = score_info["score"]
        scan.status = "completed"
        scan.progress = 100
        scan.stage = "Completed"
        from datetime import datetime
        scan.completed_at = datetime.utcnow()
        db.commit()
    except Exception as e:
        log.exception("scan failed")
        scan = db.query(Scan).get(scan_id)
        if scan:
            scan.status = "failed"
            scan.error = str(e)
            db.commit()
    finally:
        pass  # cleanup_workdir(scan_id)
        CANCELLED.pop(scan_id, None)
        db.close()


def start_scan_async(scan_id: str, ipa_path: Path):
    CANCELLED.pop(scan_id, None)
    t = threading.Thread(target=run_scan, args=(scan_id, ipa_path), daemon=True)
    t.start()


def _json_safe(obj):
    try:
        json.dumps(obj)
        return obj
    except Exception:
        return json.loads(json.dumps(obj, default=str))
