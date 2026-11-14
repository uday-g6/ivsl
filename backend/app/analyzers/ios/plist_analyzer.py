import plistlib
from typing import Dict, Any
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding

def load_plist(path):
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        return {}

class AppInfoAnalyzer(BaseAnalyzer):
    name = "app_info"

    def run(self, ctx: AnalyzerContext):
        findings = []
        p = ctx.info_plist or {}
        if "CFBundleIdentifier" not in p:
            findings.append(RawFinding(
                rule_id="PLIST_NO_BUNDLE_ID", analyzer=self.name, category="Configuration",
                severity="medium", confidence="high",
                title="Info.plist missing CFBundleIdentifier",
                description="The bundle identifier is required for a valid iOS application."
            ))
        if not p.get("MinimumOSVersion") and not p.get("LSMinimumSystemVersion"):
            findings.append(RawFinding(
                rule_id="PLIST_NO_MIN_OS", analyzer=self.name, category="Configuration",
                severity="low", confidence="medium",
                title="No MinimumOSVersion declared",
                description="Deploying without a minimum OS version can allow unsupported devices.",
                remediation="Set MinimumOSVersion in Info.plist via build settings."
            ))
        return findings