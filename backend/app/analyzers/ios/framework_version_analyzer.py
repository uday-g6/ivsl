import plistlib
import re
from pathlib import Path
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding


def extract_plist_version(plist_path: Path) -> str:
    try:
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)
        # Try multiple keys
        for key in ("CFBundleShortVersionString", "CFBundleVersion", "Bundle version"):
            if key in data and data[key]:
                return str(data[key]).strip()
    except Exception:
        pass
    return ""


def extract_dll_version(dll_path: Path) -> str:
    try:
        import dnfile
        pe = dnfile.dnPE(str(dll_path))
        if pe.net and pe.net.mdtables and pe.net.mdtables.Assembly:
            for row in pe.net.mdtables.Assembly.rows:
                if hasattr(row, "MajorVersion"):
                    v = f"{row.MajorVersion}.{row.MinorVersion}.{row.BuildNumber}.{row.RevisionNumber}"
                    return v
    except Exception:
        pass
    return ""


def extract_version_from_path_string(path_str: str) -> str:
    """Try to find version from directory name like Foo-1.2.3."""
    m = re.search(r'-(\d+\.\d+(?:\.\d+)?)', path_str)
    return m.group(1) if m else ""


class FrameworkVersionAnalyzer(BaseAnalyzer):
    name = "framework_version"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"frameworks": []}
        seen = set()

        # 1. iOS .framework bundles
        fw_dir = ctx.app_root / "Frameworks"
        if fw_dir.exists():
            for fw in fw_dir.iterdir():
                if fw.suffix != ".framework" or not fw.is_dir():
                    continue
                name = fw.stem
                version = ""
                # Try Info.plist inside the framework
                for plist_name in ("Info.plist",):
                    p = fw / plist_name
                    if p.exists():
                        version = extract_plist_version(p)
                        if version:
                            break
                # Try Contents/Info.plist (macOS-style)
                p = fw / "Contents" / "Info.plist"
                if not version and p.exists():
                    version = extract_plist_version(p)
                # Try directory name
                if not version:
                    version = extract_version_from_path_string(fw.name)

                key = f"ios:{name}:{version}"
                if key in seen:
                    continue
                seen.add(key)
                self.result["frameworks"].append({
                    "name": name, "version": version or "unknown",
                    "platform": "iOS", "type": "framework",
                })

        # 2. Xamarin .NET DLLs
        for dll in ctx.app_root.rglob("*.dll"):
            name = dll.stem
            version = extract_dll_version(dll)
            key = f"dotnet:{name}:{version}"
            if key in seen:
                continue
            seen.add(key)
            self.result["frameworks"].append({
                "name": name, "version": version or "unknown",
                "platform": ".NET", "type": "dll",
            })

        # 3. dylibs
        for dylib in ctx.app_root.rglob("*.dylib"):
            name = dylib.stem
            version = extract_version_from_path_string(dylib.name)
            key = f"dylib:{name}:{version}"
            if key in seen:
                continue
            seen.add(key)
            self.result["frameworks"].append({
                "name": name, "version": version or "unknown",
                "platform": "iOS", "type": "dylib",
            })

        return findings
