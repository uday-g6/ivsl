from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding

class ATSAnalyzer(BaseAnalyzer):
    name = "ats"

    def run(self, ctx: AnalyzerContext):
        findings = []
        ats = (ctx.info_plist or {}).get("NSAppTransportSecurity", {}) or {}

        if ats.get("NSAllowsArbitraryLoads"):
            findings.append(RawFinding(
                rule_id="ATS_ARBITRARY_LOADS", analyzer=self.name, category="Network",
                severity="high", confidence="high",
                title="ATS globally disabled (NSAllowsArbitraryLoads = true)",
                description="Allows cleartext HTTP to any domain. Disables iOS App Transport Security globally.",
                evidence="NSAllowsArbitraryLoads = true",
                impact="Traffic can be downgraded to HTTP, exposing users to MITM.",
                remediation="Remove NSAllowsArbitraryLoads; scope exceptions to specific domains and enable NSExceptionRequiresForwardSecrecy.",
                cwe="CWE-319",
            ))
        if ats.get("NSAllowsArbitraryLoadsInWebContent"):
            findings.append(RawFinding(
                rule_id="ATS_ARBITRARY_WEB", analyzer=self.name, category="Network",
                severity="medium", confidence="high",
                title="ATS disabled for web content",
                description="WKWebView may load arbitrary HTTP resources.",
                remediation="Remove this flag and load content over HTTPS only.",
                cwe="CWE-319",
            ))
        exceptions = ats.get("NSExceptionDomains", {}) or {}
        for domain, cfg in exceptions.items():
            if not isinstance(cfg, dict):
                continue
            if cfg.get("NSExceptionAllowsInsecureHTTPLoads"):
                findings.append(RawFinding(
                    rule_id="ATS_INSECURE_DOMAIN", analyzer=self.name, category="Network",
                    severity="medium", confidence="high",
                    title=f"Insecure HTTP allowed for {domain}",
                    description="ATS exception permits plaintext HTTP for this domain.",
                    evidence=f"{domain}: NSExceptionAllowsInsecureHTTPLoads=true",
                    remediation="Remove the exception or enforce HTTPS.",
                    cwe="CWE-319",
                ))
            tls = cfg.get("NSExceptionMinimumTLSVersion")
            if tls in ("TLSv1.0", "TLSv1.1"):
                findings.append(RawFinding(
                    rule_id="ATS_WEAK_TLS", analyzer=self.name, category="Network",
                    severity="medium", confidence="high",
                    title=f"Weak TLS version for {domain}",
                    description=f"Domain allows {tls}.",
                    remediation="Require TLS 1.2+ (NSExceptionMinimumTLSVersion = TLSv1.2).",
                    cwe="CWE-326",
                ))
        return findings