from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding


class FrameworkAnalyzer(BaseAnalyzer):
    name = "frameworks"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"frameworks": []}
        fw_dir = ctx.app_root / "Frameworks"
        if not fw_dir.exists():
            return findings
        for item in sorted(fw_dir.iterdir()):
            if item.suffix not in (".framework", ".dylib"):
                continue
            self.result["frameworks"].append({
                "name": item.name,
                "type": item.suffix.lstrip("."),
            })
        return findings
