from pathlib import Path
from typing import Dict, Any, List
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding

try:
    import lief
    HAVE_LIEF = True
except Exception:
    HAVE_LIEF = False

STACK_CANARY_SYMS = {"__stack_chk_fail", "__stack_chk_guard", "___stack_chk_fail", "___stack_chk_guard"}

class MachOAnalyzer(BaseAnalyzer):
    name = "macho"

    def run(self, ctx: AnalyzerContext):
        findings: List[RawFinding] = []
        self.result: Dict[str, Any] = {"available": HAVE_LIEF, "binaries": [], "objc_classes": [], "swift_types": [], "libraries": []}
        if not ctx.executable_path or not Path(ctx.executable_path).exists():
            return findings
        if not HAVE_LIEF:
            return findings

        try:
            fat = lief.MachO.parse(str(ctx.executable_path))
        except Exception as e:
            findings.append(RawFinding(rule_id="MACHO_PARSE_ERROR", analyzer=self.name, category="Binary", severity="info", confidence="low", title="Mach-O parse error", description=str(e)))
            return findings

        if fat is None:
            return findings

        binaries = fat if hasattr(fat, "__iter__") else [fat]
        for binary in binaries:
            self._analyze_binary(binary, findings)
        return findings

    def _analyze_binary(self, bin, findings: List[RawFinding]):
        arch = str(bin.header.cpu_type).split(".")[-1] if bin.header else "unknown"
        b = {"arch": arch, "pie": False, "stack_canary": "unknown", "encrypted": False, "cryptid": None}
        
        try:
            b["pie"] = bool(bin.header.has(lief.MachO.HEADER_FLAGS.PIE))
        except Exception:
            pass
        if not b["pie"]:
            findings.append(RawFinding(rule_id="MACHO_NO_PIE", analyzer=self.name, category="Binary", severity="high", confidence="high", title=f"PIE disabled ({arch})", description="Position Independent Executable flag is not set.", impact="Enables predictable memory layout, weakening ASLR.", remediation="Enable PIE in the Xcode build settings.", cwe="CWE-119"))
            
        try:
            for lib in bin.libraries:
                self.result["libraries"].append(lib.name)
        except Exception:
            pass
            
        try:
            for cmd in bin.commands:
                if isinstance(cmd, lief.MachO.EncryptionInfo):
                    b["encrypted"] = cmd.crypt_id != 0
                    b["cryptid"] = cmd.crypt_id
        except Exception:
            pass

        try:
            syms = set()
            for sym in bin.symbols:
                syms.add(sym.name)
                if sym.name.startswith("_OBJC_CLASS_$_"):
                    cls = sym.name.replace("_OBJC_CLASS_$_", "")
                    if cls not in self.result["objc_classes"]:
                        self.result["objc_classes"].append(cls)
                if sym.name.startswith("_$s"): 
                    parts = sym.name.split("C")
                    if len(parts) > 1 and len(parts[1]) > 3:
                        swift_cls = parts[1][:20]
                        if swift_cls not in self.result["swift_types"]:
                            self.result["swift_types"].append(swift_cls)

            if STACK_CANARY_SYMS & syms:
                b["stack_canary"] = "detected"
            else:
                b["stack_canary"] = "not_detected"
        except Exception:
            pass

        if b["stack_canary"] == "not_detected":
            findings.append(RawFinding(rule_id="MACHO_NO_STACK_CANARY", analyzer=self.name, category="Binary", severity="medium", confidence="medium", title=f"Stack canary symbols not found ({arch})", description="Neither __stack_chk_fail nor __stack_chk_guard present.", remediation="Build with -fstack-protector-all.", cwe="CWE-121"))

        if b["cryptid"] == 0:
            findings.append(RawFinding(rule_id="MACHO_UNENCRYPTED", analyzer=self.name, category="Binary", severity="info", confidence="high", title=f"Binary is not App Store encrypted ({arch})", description="cryptid=0 indicates the binary is decrypted (common for enterprise/dev builds)."))
        self.result["binaries"].append(b)
