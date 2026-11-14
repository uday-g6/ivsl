import re
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding


PATTERNS = {
    "DEV_PATH": (
        re.compile(r"/Users/[A-Za-z0-9_.\-]+/[A-Za-z0-9_./\-]+"),
        "Developer build path leaked",
        "medium",
        "Developer file paths reveal build environment and usernames.",
    ),
    "EMAIL": (
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "Email address in binary",
        "info",
        "Email address exposed in the app bundle.",
    ),
    "AWS_BUCKET": (
        re.compile(r"[a-z0-9.\-]+\.s3(?:[.-][a-z0-9\-]+)?\.amazonaws\.com"),
        "AWS S3 bucket reference",
        "low",
        "S3 bucket names can reveal infrastructure and allow enumeration.",
    ),
    "GCS_BUCKET": (
        re.compile(r"storage\.googleapis\.com/[A-Za-z0-9_.\-]+"),
        "Google Cloud Storage bucket reference",
        "low",
        "GCS bucket names can reveal infrastructure.",
    ),
    "INTERNAL_HOST": (
        re.compile(r"\b(?:[a-z0-9\-]+\.)+(?:internal|corp|local|lan|dev|staging|test|qa)\.[a-z]{2,}\b", re.I),
        "Internal/staging hostname",
        "medium",
        "Internal infrastructure hostnames exposed in binary.",
    ),
    "AZURE_BLOB": (
        re.compile(r"[a-z0-9]+\.blob\.core\.windows\.net"),
        "Azure Blob Storage reference",
        "low",
        "Azure blob storage account reference.",
    ),
    "PRIVATE_IP": (
        re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
        "Private/internal IP address",
        "low",
        "Internal IP addresses exposed.",
    ),
    "GITHUB_REPO": (
        re.compile(r"github\.com/[A-Za-z0-9_.\-]+/(?:[A-Za-z0-9_.\-]+)"),
        "GitHub repository reference",
        "info",
        "GitHub repository URL in binary.",
    ),
    "DATABASE_URL": (
        re.compile(r"(?:postgres|mysql|mongodb|redis)://[^\s\"'<>]{5,150}"),
        "Database URL in binary",
        "critical",
        "Full database connection string exposed — likely contains credentials.",
    ),
}


class InfoDisclosureAnalyzer(BaseAnalyzer):
    name = "info_disclosure"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"matches": []}
        seen = set()

        if not ctx.executable_path or not ctx.executable_path.exists():
            return findings

        try:
            raw = ctx.executable_path.read_bytes()[:10_000_000]
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            return findings

        for rule_id, (pattern, title, severity, description) in PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0)[:200]
                key = f"{rule_id}:{value[:80]}"
                if key in seen:
                    continue
                seen.add(key)

                # Skip if found in a comment-only context (very rough filter)
                if rule_id == "EMAIL":
                    # Skip common false positives
                    if any(x in value.lower() for x in ["@example.com", "@test.com", "noreply", "apple.com", "xamarin.com"]):
                        continue

                evidence = value if severity in ("info", "low") else value[:40] + "..." + value[-20:]
                findings.append(RawFinding(
                    rule_id=f"INFO_{rule_id}",
                    analyzer=self.name, category="Info Disclosure",
                    severity=severity, confidence="medium",
                    title=title,
                    description=description,
                    file_path="<Binary Executable>",
                    evidence=evidence,
                    remediation="Remove from production build or restrict to debug configurations.",
                ))
                self.result["matches"].append({"rule_id": rule_id, "value": value[:200], "severity": severity})

                if len(findings) > 50:  # Cap noise
                    return findings

        return findings
