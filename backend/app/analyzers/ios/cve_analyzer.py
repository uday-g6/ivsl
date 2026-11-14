import json
from pathlib import Path
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding
from app.analyzers.ios.framework_version_analyzer import FrameworkVersionAnalyzer


def version_tuple(v: str):
    """Parse '1.2.3' -> (1, 2, 3). Non-numeric parts become 0."""
    parts = []
    for p in str(v).replace("-", ".").split(".")[:5]:
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def version_lt(a: str, b: str) -> bool:
    try:
        return version_tuple(a) < version_tuple(b)
    except Exception:
        return False


class CVEAnalyzer(BaseAnalyzer):
    name = "cve"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"matches": [], "frameworks_checked": 0}

        # Load CVE DB
        cve_db_path = Path(__file__).resolve().parent.parent.parent.parent / "rules" / "cve_cache" / "curated_cves.json"
        if not cve_db_path.exists():
            self.result["error"] = "CVE database missing. Run scripts/download_cve_db.py"
            return findings

        try:
            cve_db = json.loads(cve_db_path.read_text())
        except Exception as e:
            self.result["error"] = f"Failed to load CVE DB: {e}"
            return findings

        # Get frameworks (reuse FrameworkVersionAnalyzer)
        fw_an = FrameworkVersionAnalyzer()
        fw_an.run(ctx)
        frameworks = fw_an.result.get("frameworks", [])
        self.result["frameworks_checked"] = len(frameworks)

        for fw in frameworks:
            name = fw["name"]
            version = fw["version"]
            if version in ("unknown", "", None):
                continue

            for cve in cve_db:
                # Match library name (case-insensitive substring)
                if cve["library"].lower() not in name.lower():
                    continue
                # Check version < vulnerable_version
                if version_lt(version, cve["version_lt"]):
                    findings.append(RawFinding(
                        rule_id="CVE_MATCH",
                        analyzer=self.name,
                        category="Vulnerable Component",
                        severity=cve["severity"],
                        confidence="medium",
                        title=f"{name} {version} vulnerable to {cve['cve']}",
                        description=(
                            f"{name} version {version} is affected by {cve['cve']}. "
                            f"Vulnerable versions: < {cve['version_lt']}. "
                            f"{cve['description']}"
                        ),
                        file_path=f"Frameworks/{name}",
                        evidence=f"{name} {version} < {cve['version_lt']} ({cve['cve']})",
                        impact="Known publicly disclosed vulnerability affecting the library in use.",
                        remediation=f"Upgrade {name} to version {cve['version_lt']} or later.",
                        cwe="CWE-1104",
                    ))
                    self.result["matches"].append({
                        "library": name, "version": version,
                        "cve": cve["cve"], "fixed_in": cve["version_lt"],
                        "severity": cve["severity"],
                    })

        return findings
