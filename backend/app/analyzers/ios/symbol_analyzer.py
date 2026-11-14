from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding

try:
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False


# Dangerous symbols to detect
DANGEROUS_SYMBOLS = {
    # Buffer overflow risks
    "strcpy": ("high", "CWE-120", "Unbounded string copy — buffer overflow risk."),
    "strcat": ("high", "CWE-120", "Unbounded string concatenation."),
    "sprintf": ("high", "CWE-134", "Unbounded formatted string write."),
    "vsprintf": ("high", "CWE-134", "Unbounded formatted string write."),
    "gets": ("critical", "CWE-242", "Deprecated unsafe input — removed from iOS."),
    "memcpy": ("medium", "CWE-787", "Unbounded memory copy."),
    # Command injection
    "system": ("high", "CWE-78", "Shell command execution."),
    "popen": ("high", "CWE-78", "Shell pipe execution."),
    "exec": ("high", "CWE-78", "Process execution."),
    # Dynamic loading
    "dlopen": ("medium", "CWE-114", "Dynamic library loading."),
    "dlsym": ("medium", "CWE-114", "Dynamic symbol resolution."),
    # Anti-debugging
    "ptrace": ("medium", "CWE-693", "Debugging API — used for anti-debugging."),
    "sysctl": ("low", "CWE-693", "System control — often used for anti-debugging."),
    # Environment attacks
    "getenv": ("low", "CWE-200", "Environment variable access."),
    "setenv": ("low", "CWE-200", "Environment variable modification."),
    # Crypto / TLS
    "SecTrustEvaluate": ("info", "CWE-295", "TLS trust evaluation — verify implementation."),
    "SecItemCopyMatching": ("info", "CWE-312", "Keychain access."),
    "CCCrypt": ("medium", "CWE-327", "CommonCrypto API — verify algorithm choice."),
    # Logging
    "NSLog": ("low", "CWE-532", "Logs to system console — may leak sensitive data."),
    "printf": ("low", "CWE-532", "Printf to stdout — may leak data."),
}


class SymbolAnalyzer(BaseAnalyzer):
    name = "symbols"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"dangerous_symbols": [], "total_exports": 0, "total_imports": 0}

        if not HAVE_LIEF:
            return findings
        if not ctx.executable_path or not ctx.executable_path.exists():
            return findings

        try:
            fat = lief.MachO.parse(str(ctx.executable_path))
        except Exception:
            return findings
        if fat is None:
            return findings

        binaries = fat if hasattr(fat, "__iter__") else [fat]

        all_symbols = set()
        for binary in binaries:
            try:
                for sym in binary.symbols:
                    name = sym.name
                    # Clean leading underscore
                    if name.startswith("_"):
                        name = name[1:]
                    all_symbols.add(name)
            except Exception:
                pass
            try:
                self.result["total_exports"] += len(list(binary.exported_symbols))
            except Exception:
                pass
            try:
                self.result["total_imports"] += len(list(binary.imported_symbols))
            except Exception:
                pass

        # Check for dangerous symbols
        for sym_name, (severity, cwe, description) in DANGEROUS_SYMBOLS.items():
            if sym_name in all_symbols:
                self.result["dangerous_symbols"].append({"name": sym_name, "severity": severity})
                findings.append(RawFinding(
                    rule_id=f"SYMBOL_DANGEROUS_{sym_name.upper()}",
                    analyzer=self.name, category="Symbols",
                    severity=severity, confidence="high",
                    title=f"Dangerous symbol referenced: {sym_name}",
                    description=description,
                    file_path="<Binary Executable>",
                    evidence=f"Symbol '{sym_name}' found in binary",
                    remediation=f"Review usage of {sym_name}. Use safer alternatives or validate inputs strictly.",
                    cwe=cwe,
                ))

        return findings
