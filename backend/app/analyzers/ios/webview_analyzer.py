import re
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding


WEBVIEW_APIS = {
    "UIWebView": ("critical", "Deprecated UIWebView detected. Apple will reject this."),
    "WKWebView": ("info", "WKWebView detected (secure, current standard)."),
    "WKScriptMessageHandler": ("medium", "JavaScript bridge to native code detected."),
    "WKUserContentController": ("medium", "WKUserContentController can inject JavaScript."),
    "evaluateJavaScript": ("medium", "evaluateJavaScript allows arbitrary JS execution."),
    "loadHTMLString": ("low", "loadHTMLString can load untrusted HTML."),
    "loadRequest": ("info", "WebView loads URL requests."),
    "javaScriptEnabled": ("medium", "JavaScript is enabled in WebView."),
    "allowsInlineMediaPlayback": ("low", "Inline media playback enabled."),
    "setValue:forKey:": ("medium", "KVC access on WKWebView can be abused."),
    "JSContext": ("medium", "JSContext allows JavaScript execution from native."),
    "evaluateScript": ("medium", "JavaScriptCore evaluateScript allows JS injection."),
}


class WebViewAnalyzer(BaseAnalyzer):
    name = "webview"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"detected_apis": []}
        seen = set()

        if not ctx.executable_path or not ctx.executable_path.exists():
            return findings

        try:
            raw = ctx.executable_path.read_bytes()[:10_000_000]
        except Exception:
            return findings

        for api, (severity, desc) in WEBVIEW_APIS.items():
            api_bytes = api.encode()
            if api_bytes in raw:
                self.result["detected_apis"].append({"api": api, "severity": severity})
                if api not in seen:
                    seen.add(api)
                    findings.append(RawFinding(
                        rule_id=f"WEBVIEW_{api.upper().replace(':', '_')}",
                        analyzer=self.name, category="WebView",
                        severity=severity, confidence="high",
                        title=f"WebView API detected: {api}",
                        description=desc,
                        evidence=f"API '{api}' referenced in binary",
                        remediation="If using WKWebView, ensure JavaScript bridge validates all input. If using UIWebView, migrate to WKWebView immediately.",
                    ))

        # Check ATS WebContent exception
        plist = ctx.info_plist or {}
        ats = plist.get("NSAppTransportSecurity", {}) or {}
        if ats.get("NSAllowsArbitraryLoadsInWebContent"):
            findings.append(RawFinding(
                rule_id="WEBVIEW_ATS_DISABLED",
                analyzer=self.name, category="WebView",
                severity="high", confidence="high",
                title="ATS disabled for WebView content",
                description="NSAllowsArbitraryLoadsInWebContent is true. WKWebView can load HTTP content.",
                evidence="NSAllowsArbitraryLoadsInWebContent = true",
                remediation="Remove this flag and ensure all WebView content is served over HTTPS.",
                cwe="CWE-319",
            ))

        return findings
