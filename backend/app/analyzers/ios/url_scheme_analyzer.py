from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding


# Sensitive patterns that shouldn't be in URL schemes
SENSITIVE_PARAM_KEYWORDS = [
    "token", "password", "secret", "key", "auth", "session",
    "api", "id", "user", "account", "credential", "pin", "otp",
]


class URLSchemeAnalyzer(BaseAnalyzer):
    name = "url_schemes"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"url_schemes": [], "query_schemes": [], "document_types": []}
        plist = ctx.info_plist or {}

        # 1. Custom URL Schemes
        url_types = plist.get("CFBundleURLTypes", []) or []
        seen_schemes = set()
        for entry in url_types:
            schemes = entry.get("CFBundleURLSchemes", []) or []
            for scheme in schemes:
                scheme_lower = scheme.lower()
                if scheme_lower in seen_schemes:
                    findings.append(RawFinding(
                        rule_id="URL_SCHEME_DUPLICATE",
                        analyzer=self.name, category="URL Schemes",
                        severity="low", confidence="high",
                        title=f"Duplicate URL scheme: {scheme}",
                        description="The same URL scheme is declared multiple times.",
                        evidence=scheme,
                        remediation="Remove duplicate scheme declarations.",
                        cwe="CWE-1021",
                    ))
                seen_schemes.add(scheme_lower)
                self.result["url_schemes"].append({"scheme": scheme})

                # Check for sensitive keyword in scheme
                if any(k in scheme_lower for k in SENSITIVE_PARAM_KEYWORDS):
                    findings.append(RawFinding(
                        rule_id="URL_SCHEME_SENSITIVE",
                        analyzer=self.name, category="URL Schemes",
                        severity="medium", confidence="medium",
                        title=f"Sensitive keyword in URL scheme: {scheme}",
                        description="The URL scheme name suggests sensitive data may be passed through it.",
                        evidence=scheme,
                        remediation="Avoid using sensitive keywords in URL schemes; validate all inbound parameters.",
                        cwe="CWE-200",
                    ))

                # Check for overly generic schemes (likely to collide)
                if len(scheme) <= 4:
                    findings.append(RawFinding(
                        rule_id="URL_SCHEME_TOO_GENERIC",
                        analyzer=self.name, category="URL Schemes",
                        severity="medium", confidence="medium",
                        title=f"URL scheme too generic: {scheme}",
                        description="Short URL schemes can be hijacked by other apps.",
                        evidence=scheme,
                        remediation="Use a reverse-DNS style scheme (e.g., com.company.app).",
                        cwe="CWE-1021",
                    ))

        # 2. Associated Domains (Universal Links)
        ent_path = ctx.app_root / "embedded.mobileprovision"
        if ent_path.exists():
            try:
                import plistlib
                raw = ent_path.read_bytes()
                start = raw.find(b"<?xml")
                end = raw.rfind(b"</plist>")
                if start != -1 and end != -1:
                    data = plistlib.loads(raw[start:end + len(b"</plist>")])
                    ents = data.get("Entitlements", {}) or {}
                    domains = ents.get("com.apple.developer.associated-domains", [])
                    if isinstance(domains, list):
                        for d in domains:
                            self.result["url_schemes"].append({"associated_domain": d})
                            # Find appslinks
                            if "applinks:" in str(d):
                                findings.append(RawFinding(
                                    rule_id="URL_UNIVERSAL_LINK",
                                    analyzer=self.name, category="URL Schemes",
                                    severity="info", confidence="high",
                                    title=f"Universal Link: {d}",
                                    description="App registers a Universal Link domain.",
                                    evidence=d,
                                    remediation="Ensure apple-app-site-association is properly configured server-side.",
                                ))
            except Exception:
                pass

        # 3. Document Types
        doc_types = plist.get("CFBundleDocumentTypes", []) or []
        for dt in doc_types:
            name = dt.get("CFBundleTypeName", "")
            self.result["document_types"].append({"name": name})
            if name:
                findings.append(RawFinding(
                    rule_id="URL_DOCUMENT_TYPE",
                    analyzer=self.name, category="URL Schemes",
                    severity="info", confidence="high",
                    title=f"Document type registered: {name}",
                    description="App handles custom document types. Validate all input files.",
                    evidence=name,
                    remediation="Validate all document input and handle malformed files gracefully.",
                ))

        # 4. Query Schemes (what the app opens)
        queries = plist.get("LSApplicationQueriesSchemes", []) or []
        self.result["query_schemes"] = queries
        if len(queries) > 20:
            findings.append(RawFinding(
                rule_id="URL_EXCESSIVE_QUERY_SCHEMES",
                analyzer=self.name, category="URL Schemes",
                severity="medium", confidence="high",
                title=f"Excessive query schemes declared ({len(queries)})",
                description="App can query presence of many other apps — data leakage risk.",
                evidence=f"{len(queries)} schemes",
                remediation="Audit LSApplicationQueriesSchemes and remove unnecessary entries.",
                cwe="CWE-200",
            ))

        return findings
