import plistlib
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding


class EntitlementAnalyzer(BaseAnalyzer):
    name = "entitlements"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"entitlements": {}, "provisioning": {}}

        prov = ctx.app_root / "embedded.mobileprovision"
        if prov.exists():
            try:
                raw = prov.read_bytes()
                start = raw.find(b"<?xml")
                end = raw.rfind(b"</plist>")
                if start != -1 and end != -1:
                    data = plistlib.loads(raw[start:end + len(b"</plist>")])
                    ents = {}
                    for k, v in (data.get("Entitlements") or {}).items():
                        try:
                            ents[k] = str(v)
                        except Exception:
                            ents[k] = "<unserializable>"
                    self.result["provisioning"] = {
                        "Name": data.get("Name"),
                        "AppIDName": data.get("AppIDName"),
                        "TeamIdentifier": data.get("TeamIdentifier"),
                        "ExpirationDate": str(data.get("ExpirationDate")),
                        "Entitlements": ents,
                    }
            except Exception as e:
                self.result["provisioning"] = {"error": str(e)}

        ents = (self.result.get("provisioning") or {}).get("Entitlements", {}) or {}
        if str(ents.get("get-task-allow", "")).lower() == "true":
            findings.append(RawFinding(
                rule_id="ENT_DEBUG_ENTITLEMENT",
                analyzer=self.name,
                category="Debug",
                severity="high",
                confidence="high",
                title="get-task-allow entitlement present",
                description="Provisioning profile grants debugging to the app. "
                            "Distribution profiles must not include this.",
                remediation="Rebuild the app with a distribution profile.",
                cwe="CWE-489",
            ))
        return findings
