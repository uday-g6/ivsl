import plistlib
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding


class PrivacyManifestAnalyzer(BaseAnalyzer):
    name = "privacy"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"manifests": []}
        for p in ctx.app_root.rglob("PrivacyInfo.xcprivacy"):
            try:
                with open(p, "rb") as f:
                    data = plistlib.load(f)
            except Exception as e:
                findings.append(RawFinding(
                    rule_id="PRIVACY_INVALID",
                    analyzer=self.name,
                    category="Privacy",
                    severity="low",
                    confidence="medium",
                    title="Invalid PrivacyInfo.xcprivacy",
                    description=str(e),
                    file_path=str(p.relative_to(ctx.app_root)),
                ))
                continue
            tracking = data.get("NSPrivacyTracking")
            domains = data.get("NSPrivacyTrackingDomains", []) or []
            collected = data.get("NSPrivacyCollectedDataTypes", []) or []
            accessed = data.get("NSPrivacyAccessedAPITypes", []) or []
            self.result["manifests"].append({
                "path": str(p.relative_to(ctx.app_root)),
                "tracking": tracking,
                "tracking_domains": domains,
                "collected_data": len(collected),
                "accessed_apis": len(accessed),
            })
            if tracking and not domains:
                findings.append(RawFinding(
                    rule_id="PRIVACY_TRACKING_NO_DOMAINS",
                    analyzer=self.name,
                    category="Privacy",
                    severity="medium",
                    confidence="medium",
                    title="Tracking declared without tracking domains",
                    description="NSPrivacyTracking=true but NSPrivacyTrackingDomains is empty.",
                    file_path=str(p.relative_to(ctx.app_root)),
                    remediation="Declare tracking domains or disable tracking.",
                ))
        if not self.result["manifests"]:
            findings.append(RawFinding(
                rule_id="PRIVACY_NO_MANIFEST",
                analyzer=self.name,
                category="Privacy",
                severity="low",
                confidence="medium",
                title="No PrivacyInfo.xcprivacy found",
                description="Apple requires privacy manifests for apps using certain APIs.",
                remediation="Add PrivacyInfo.xcprivacy with required reasons.",
            ))
        return findings
