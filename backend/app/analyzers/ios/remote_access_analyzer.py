from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding

REMOTE_ACCESS_SCHEMES = {
    "teamviewer": "TeamViewer",
    "teamviewerqs": "TeamViewer QuickSupport",
    "teamviewer8": "TeamViewer 8",
    "teamviewer10": "TeamViewer 10",
    "teamviewer11": "TeamViewer 11",
    "anydesk": "AnyDesk",
    "anyviewer": "AnyViewer",
    "vncviewer": "VNC Viewer",
    "gotomypc": "GoToMyPC",
    "msrdc": "Microsoft Remote Desktop",
    "airdroid": "AirDroid",
    "kdeconnect": "KDE Connect",
    "rdm": "Remote Desktop Manager",
    "logmein": "LogMeIn",
    "splashtop": "Splashtop",
    "jumpdesktop": "Jump Desktop",
}

JAILBREAK_SCHEMES = {
    "cydia": "Cydia (jailbreak)",
    "sileo": "Sileo (jailbreak)",
    "zbra": "Zebra (jailbreak)",
    "installer": "Installer (jailbreak)",
    "undecimus": "unc0ver (jailbreak)",
    "checkra1n": "checkra1n (jailbreak)",
}


class RemoteAccessAnalyzer(BaseAnalyzer):
    name = "remote_access"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"remote_tools": [], "jailbreak_tools": []}
        plist = ctx.info_plist or {}
        queries = plist.get("LSApplicationQueriesSchemes", []) or []
        queries_lower = [q.lower() for q in queries]

        for q in queries_lower:
            if q in REMOTE_ACCESS_SCHEMES:
                self.result["remote_tools"].append({"scheme": q, "name": REMOTE_ACCESS_SCHEMES[q]})

        if self.result["remote_tools"]:
            tool_names = [t["name"] for t in self.result["remote_tools"]]
            findings.append(RawFinding(
                rule_id="REMOTE_ACCESS_TOOL_DETECTION",
                analyzer=self.name, category="Privacy",
                severity="medium", confidence="high",
                title=f"App detects {len(tool_names)} remote-access tools",
                description=(
                    f"App queries for {len(tool_names)} remote-access tools. "
                    f"If this is for fraud detection, document it in the privacy policy. "
                    f"If not, this is a privacy concern. Detected: {', '.join(tool_names)}"
                ),
                evidence=", ".join([t["scheme"] for t in self.result["remote_tools"]]),
                remediation="Verify necessity, document in privacy policy, ensure only used for legitimate fraud prevention.",
                cwe="CWE-200",
            ))

        for q in queries_lower:
            if q in JAILBREAK_SCHEMES:
                self.result["jailbreak_tools"].append({"scheme": q, "name": JAILBREAK_SCHEMES[q]})

        if self.result["jailbreak_tools"]:
            tool_names = [t["name"] for t in self.result["jailbreak_tools"]]
            findings.append(RawFinding(
                rule_id="JAILBREAK_DETECTION_PRESENT",
                analyzer=self.name, category="Security",
                severity="info", confidence="high",
                title=f"App implements jailbreak detection ({len(tool_names)} checks)",
                description=f"Good practice for banking apps. Detected: {', '.join(tool_names)}.",
                evidence=", ".join([t["scheme"] for t in self.result["jailbreak_tools"]]),
                remediation="Ensure jailbreak detection can't be bypassed by Frida/hooks.",
            ))

        return findings
