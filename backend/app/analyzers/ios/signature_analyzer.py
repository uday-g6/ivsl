from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding


class SignatureAnalyzer(BaseAnalyzer):
    name = "signature"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {
            "signed_bundle": False,
            "provisioning_profile": False,
            "limitation": "",
            "note": "Cryptographic signature verification is not performed by IPA Sentinel.",
        }
        code_res = ctx.app_root / "_CodeSignature" / "CodeResources"
        if code_res.exists():
            self.result["signed_bundle"] = True
        else:
            self.result["limitation"] = "No _CodeSignature/CodeResources - bundle may be unsigned."
            findings.append(RawFinding(
                rule_id="SIG_NO_CODE_SIGNATURE",
                analyzer=self.name,
                category="Signing",
                severity="medium",
                confidence="medium",
                title="No _CodeSignature/CodeResources found",
                description="Bundle may not be properly code-signed.",
                remediation="Sign the app with a valid Apple distribution certificate.",
            ))
        if (ctx.app_root / "embedded.mobileprovision").exists():
            self.result["provisioning_profile"] = True
        return findings
