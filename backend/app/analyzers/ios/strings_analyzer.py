import re
import string
from pathlib import Path
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding
from app.analyzers.ios.secret_analyzer import scan_text

class StringsAnalyzer(BaseAnalyzer):
    name = "strings"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"total_strings": 0, "sample_strings": []}
        
        if not ctx.executable_path or not Path(ctx.executable_path).exists():
            return findings

        try:
            # Read binary in chunks to avoid memory spikes
            with open(ctx.executable_path, "rb") as f:
                data = f.read()
            
            # Extract ASCII strings of length >= 6
            pattern = re.compile(b'[\\x20-\\x7E]{6,}')
            strings = [m.group(0).decode('ascii') for m in pattern.finditer(data)]
            self.result["total_strings"] = len(strings)
            self.result["sample_strings"] = strings[:200] # Save first 200 for UI preview
            
            # Join strings and scan for secrets
            # We join with newlines to preserve line context
            text_blob = "\n".join(strings)
            secret_findings = scan_text(text_blob, rel_path="<Binary Strings>")
            
            # Filter out duplicates and tag them as binary findings
            for sf in secret_findings:
                sf.analyzer = "strings"
                sf.rule_id = f"BIN_{sf.rule_id}"
                sf.title = f"Hardcoded {sf.title} in Binary"
                sf.confidence = "high" # Binary strings have higher confidence
                findings.append(sf)
                
        except Exception as e:
            pass
            
        return findings
