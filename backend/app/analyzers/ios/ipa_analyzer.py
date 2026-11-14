from pathlib import Path
from typing import Optional
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding

class IPAPackageAnalyzer(BaseAnalyzer):
    name = "ipa_package"

    def run(self, ctx: AnalyzerContext):
        findings = []
        payload = ctx.app_root.parent
        files = ctx.all_files

        if not ctx.executable_path or not Path(ctx.executable_path).exists():
            findings.append(RawFinding(
                rule_id="IPA_NO_EXECUTABLE", analyzer=self.name, category="Packaging",
                severity="high", confidence="high",
                title="CFBundleExecutable missing or not found in bundle",
                description="Info.plist declares an executable that is not present in the .app bundle.",
                remediation="Rebuild the IPA ensuring the executable is packaged under the .app."
            ))

        # Unexpected top-level items in Payload
        payload_entries = {p.name for p in payload.iterdir()}
        apps = [n for n in payload_entries if n.endswith(".app")]
        if len(apps) == 0:
            findings.append(RawFinding(
                rule_id="IPA_NO_APP_BUNDLE", analyzer=self.name, category="Packaging",
                severity="high", confidence="high",
                title="No .app bundle found inside Payload/",
                description="A valid iOS IPA must contain Payload/<Name>.app/.",
                remediation="Verify the IPA was produced by a proper iOS archive export."
            ))
        if len(apps) > 1:
            findings.append(RawFinding(
                rule_id="IPA_MULTIPLE_APP_BUNDLES", analyzer=self.name, category="Packaging",
                severity="medium", confidence="high",
                title=f"Multiple .app bundles found ({len(apps)})",
                description="A production IPA normally contains exactly one main .app bundle.",
                remediation="Inspect the archive; remove unnecessary bundles before distribution."
            ))

        # Duplicate file detection (by name only, cheap heuristic)
        seen = {}
        for f in files:
            seen.setdefault(f.name, 0)
            seen[f.name] += 1
        dups = [n for n, c in seen.items() if c > 1]
        if len(dups) > 20:
            findings.append(RawFinding(
                rule_id="IPA_MANY_DUPLICATES", analyzer=self.name, category="Packaging",
                severity="info", confidence="low",
                title=f"{len(dups)} duplicate filenames detected",
                description="Large numbers of same-named resources can indicate sloppy build packaging.",
            ))
        return findings
    