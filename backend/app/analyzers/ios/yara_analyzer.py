import yara
from pathlib import Path
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding

# Built-in YARA rules for iOS security testing
YARA_RULES = '''
rule iOS_Hardcoded_AWS {
    meta:
        description = "Detects hardcoded AWS Access Key"
        severity = "critical"
        cwe = "CWE-798"
    strings:
        $aws1 = /AKIA[0-9A-Z]{16}/
        $aws2 = /ASIA[0-9A-Z]{16}/
    condition:
        any of them
}

rule iOS_Debug_Enabled {
    meta:
        description = "Detects debugging enabled in binary"
        severity = "high"
        cwe = "CWE-489"
    strings:
        $debug1 = "get-task-allow"
        $debug2 = "ptrace"
        $debug3 = "sysctl"
    condition:
        any of them
}

rule iOS_Jailbreak_Check {
    meta:
        description = "Detects jailbreak detection evasion strings"
        severity = "info"
        cwe = "CWE-693"
    strings:
        $jb1 = "/Applications/Cydia.app"
        $jb2 = "/bin/bash"
        $jb3 = "frida"
        $jb4 = "Substrate"
        $jb5 = "cycript"
    condition:
        any of them
}

rule Xamarin_Hardcoded_Connection {
    meta:
        description = "Detects hardcoded DB or API connection strings in .NET DLLs"
        severity = "high"
        cwe = "CWE-798"
    strings:
        $sql = "Server=" nocase
        $sql2 = "Data Source=" nocase
        $http = "http://" nocase
        $pass = "Password=" nocase
    condition:
        any of them
}

rule iOS_Weak_Crypto {
    meta:
        description = "Detects weak cryptographic algorithms"
        severity = "medium"
        cwe = "CWE-327"
    strings:
        $crypto1 = "MD5"
        $crypto2 = "SHA1"
        $crypto3 = "DES"
        $crypto4 = "ECB"
    condition:
        any of them
}
'''

class YaraAnalyzer(BaseAnalyzer):
    name = "yara"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"matches": []}
        
        try:
            rules = yara.compile(source=YARA_RULES)
        except Exception:
            return findings

        # Scan the executable
        targets = []
        if ctx.executable_path and Path(ctx.executable_path).exists():
            targets.append(ctx.executable_path)
            
        # Also scan text files
        for f in ctx.all_files:
            if f.suffix in (".plist", ".json", ".xml", ".txt", ".strings", ".dll", ".exe") and f.stat().st_size < 10*1024*1024:
                targets.append(f)

        for target in targets:
            try:
                matches = rules.match(str(target))
                for m in matches:
                    rule_id = f"YARA_{m.rule}"
                    sev = m.meta.get("severity", "medium")
                    desc = m.meta.get("description", "YARA rule matched.")
                    cwe = m.meta.get("cwe", "")
                    
                    # Extract matched string for evidence
                    evidence = ""
                    if m.strings:
                        # m.strings is a list of tuples (offset, identifier, data)
                        evidence = m.strings[0][2].decode('utf-8', errors='replace')[:50]
                    
                    findings.append(RawFinding(
                        rule_id=rule_id,
                        analyzer=self.name,
                        category="YARA",
                        severity=sev,
                        confidence="high",
                        title=desc,
                        description=f"Matched YARA rule: {m.rule}",
                        file_path=str(target.relative_to(ctx.app_root)) if target != ctx.executable_path else "Binary Executable",
                        evidence=evidence,
                        cwe=cwe,
                        remediation="Review the matched strings and remove or obfuscate sensitive patterns."
                    ))
                    self.result["matches"].append({"rule": m.rule, "file": str(target.name), "evidence": evidence})
            except Exception:
                pass

        return findings
