import re
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding


DEBUG_PATTERNS = {
    "NSLog": ("low", "NSLog writes to system console — may leak data."),
    "print(": ("info", "print() output may appear in logs."),
    "assert(": ("low", "Assertions may leak state in debug builds."),
    "O0": ("medium", "Optimization level O0 — debug build detected."),
    "dSYM": ("medium", "dSYM debug symbols file present."),
    "DEVELOPMENT": ("medium", "Development config string."),
    "STAGING": ("medium", "Staging config string."),
    "DEBUG": ("low", "Debug-related string."),
}


class DebugArtifactAnalyzer(BaseAnalyzer):
    name = "debug_artifacts"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"debug_files": [], "debug_strings": []}

        # 1. Check for debug-related files
        for pattern in ["*.dSYM", "*.debug.dylib", "*.debug", "*.xcconfig"]:
            for f in ctx.app_root.rglob(pattern):
                rel = str(f.relative_to(ctx.app_root))
                self.result["debug_files"].append(rel)
                findings.append(RawFinding(
                    rule_id="DEBUG_ARTIFACT_FILE",
                    analyzer=self.name, category="Debug Artifacts",
                    severity="medium", confidence="high",
                    title=f"Debug artifact: {rel}",
                    description="Debug files should not be in production builds.",
                    file_path=rel,
                    remediation="Remove debug artifacts from production IPA.",
                ))

        # 2. Check for unstripped binary (debug symbols present)
        if ctx.executable_path and ctx.executable_path.exists():
            try:
                if ctx.executable_path.stat().st_size > 100_000:
                    # Check for DWARF debug sections
                    raw = ctx.executable_path.read_bytes()[:5_000_000]
                    if b"__DWARF" in raw or b".debug_info" in raw:
                        findings.append(RawFinding(
                            rule_id="DEBUG_UNSTRIPPED_BINARY",
                            analyzer=self.name, category="Debug Artifacts",
                            severity="medium", confidence="high",
                            title="Unstripped binary — debug symbols present",
                            description="Binary contains DWARF debug info. Reversing is significantly easier.",
                            file_path="<Executable>",
                            evidence="DWARF debug sections found",
                            remediation="Strip debug symbols before release build.",
                        ))
            except Exception:
                pass

        # 3. Check for O0 optimization flag
        if ctx.executable_path and ctx.executable_path.exists():
            try:
                raw = ctx.executable_path.read_bytes()[:2_000_000]
                text = raw.decode("utf-8", errors="ignore")
                if "O0" in text or "O0 " in text or " O0 " in text:
                    findings.append(RawFinding(
                        rule_id="DEBUG_O0_FLAG",
                        analyzer=self.name, category="Debug Artifacts",
                        severity="medium", confidence="medium",
                        title="Optimization flag O0 detected",
                        description="Debug builds have O0 optimization. This app may not be release-optimized.",
                        evidence="O0 flag string found",
                        remediation="Build with -O2 or -Os optimization for production.",
                    ))
            except Exception:
                pass

        return findings
