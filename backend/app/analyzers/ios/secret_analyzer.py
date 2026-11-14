import re
import math
from pathlib import Path
from typing import Iterable, List, Tuple
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding

TEXT_EXTS = {".plist", ".json", ".xml", ".txt", ".js", ".html", ".strings",
             ".config", ".yml", ".yaml", ".properties", ".db", ".sqlite", ".sql",
             ".dll", ".exe", ".cs", ".java", ".kt"}

RULES = [
    # (rule_id, category, severity, regex, description, cwe)
    ("SECRET_AWS_KEY", "Secrets", "critical", re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID", "CWE-798"),
    ("SECRET_AWS_SECRET", "Secrets", "critical", re.compile(r"(?i)aws(.{0,20})?(secret|sk)[\"'\s:=]{1,3}([A-Za-z0-9/+=]{40})"), "AWS secret access key", "CWE-798"),
    ("SECRET_JWT", "Secrets", "high", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT token", "CWE-798"),
    ("SECRET_PRIVATE_KEY", "Secrets", "critical", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "Embedded private key", "CWE-798"),
    ("SECRET_GOOGLE_API", "Secrets", "high", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "Google API key", "CWE-798"),
    ("SECRET_STRIPE", "Secrets", "critical", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "Stripe live secret key", "CWE-798"),
    ("SECRET_GITHUB", "Secrets", "high", re.compile(r"ghp_[0-9A-Za-z]{36}"), "GitHub personal token", "CWE-798"),
    ("SECRET_SLACK", "Secrets", "high", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "Slack token", "CWE-798"),
    ("SECRET_BEARER", "Secrets", "medium", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.=]{20,}"), "Hardcoded Bearer token", "CWE-798"),
    ("INTERNAL_IP", "Network", "low", re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"), "Internal IP address", "CWE-200"),
    ("INTERNAL_URL", "Network", "low", re.compile(r"https?://(?:[a-z0-9-]+\.)*(?:internal|staging|dev|localhost|test)\.[a-z0-9.-]+", re.I), "Non-production endpoint", "CWE-200"),
]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def redact(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return "*" * len(v)
    return v[:4] + "*" * (len(v) - 8) + v[-4:]

def scan_text(text: str, rel_path: str) -> List[RawFinding]:
    out: List[RawFinding] = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        if len(line) > 8000:
            continue
        for rule_id, cat, sev, rx, desc, cwe in RULES:
            m = rx.search(line)
            if not m:
                continue
            token = m.group(0)
            # entropy gate for token-like values
            if rule_id in ("SECRET_AWS_SECRET", "SECRET_BEARER"):
                if shannon_entropy(token) < 3.2:
                    continue
            out.append(RawFinding(
                rule_id=rule_id, analyzer="secrets", category=cat,
                severity=sev, confidence="medium",
                title=desc, description=f"Potential {desc} detected.",
                file_path=rel_path, line=idx,
                evidence=redact(token),
                impact="Leaked secrets allow unauthorized access to backend services.",
                remediation="Remove hardcoded secrets; load from secure storage / Keychain / server-side.",
                cwe=cwe,
            ))
    return out

class SecretScannerAnalyzer(BaseAnalyzer):
    name = "secrets"

    def run(self, ctx: AnalyzerContext):
        findings: List[RawFinding] = []
        seen = set()
        for path in ctx.all_files:
            if path.suffix.lower() not in TEXT_EXTS:
                continue
            try:
                if path.stat().st_size > 5 * 1024 * 1024:
                    continue
                data = path.read_bytes()
            except Exception:
                continue
            # Skip binary-ish content
            if b"\x00" in data[:1024]:
                continue
            try:
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                continue
            rel = str(path.relative_to(ctx.app_root))
            for f in scan_text(text, rel):
                key = (f.rule_id, f.file_path, f.evidence)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(f)
        return findings