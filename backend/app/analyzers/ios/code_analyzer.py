import re
import hashlib
from pathlib import Path
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding

try:
    import dnfile
    HAVE_DNFILE = True
except ImportError:
    HAVE_DNFILE = False

# Skip framework DLLs (Microsoft/Xamarin libs, not app code)
FRAMEWORK_DLLS = {
    "mscorlib.dll", "System.dll", "System.Core.dll", "System.Data.dll",
    "System.Xml.dll", "System.Xml.Linq.dll", "System.Drawing.Common.dll",
    "System.Runtime.Serialization.dll", "System.Net.Http.dll",
    "System.Numerics.dll", "System.Runtime.Loader.dll", "System.Web.Services.dll",
    "System.ServiceModel.Internals.dll", "System.Text.Encoding.CodePages.dll",
    "System.Reactive.Core.dll", "System.Reactive.Linq.dll", "System.Reactive.Interfaces.dll",
    "Mono.Security.dll", "Mono.Cecil.dll", "Mono.Cairo.dll",
    "Newtonsoft.Json.dll", "Microsoft.AppCenter.dll", "Microsoft.AppCenter.Analytics.dll",
    "Microsoft.AppCenter.Crashes.dll", "Microsoft.Extensions.DependencyModel.dll",
    "Microsoft.DotNet.PlatformAbstractions.dll", "PInvoke.BCrypt.dll",
    "PInvoke.Kernel32.dll", "PInvoke.Windows.Core.dll",
    "Xamarin.iOS.dll", "Xamarin.Forms.Core.dll", "Xamarin.Forms.Platform.dll",
    "Xamarin.Forms.Platform.iOS.dll", "Xamarin.Forms.Xaml.dll", "Xamarin.Essentials.dll",
    "Acr.UserDialogs.dll", "Acr.DeviceInfo.dll", "Plugin.Connectivity.dll",
    "Plugin.Permissions.dll", "Plugin.Settings.dll", "Plugin.SecureStorage.dll",
    "Plugin.Media.dll", "Plugin.Iconize.dll", "BTProgressHUD.dll",
    "BouncyCastle.Crypto.dll", "iText.Kernel.dll", "iText.IO.dll", "iText.Layout.dll",
    "OpenTK-1.0.dll", "Validation.dll", "Common.Logging.dll", "Common.Logging.Core.dll",
    "PCLCrypto.dll", "TOCropBinding.dll", "Xamarin.SimplePing.iOS.dll",
}

# SQL pattern — match the original working version (looser)
# Strict SQL: keyword + FROM/INTO/SET + operator (=, @param, ?, >=, etc.)
SQL_RE = re.compile(
    r'(?i)\b(?:SELECT|INSERT|UPDATE|DELETE)\b.{1,300}?\b(?:FROM|INTO|SET|WHERE|VALUES)\b'
    r'.{1,300}?(?:=|@\w+|\?|>=|<=|<>|!=|\bLIKE\b|\bIN\s*\()'
)
DB_RE = re.compile(r'(?i)(Data Source=[^\s;]+;|Server=[^\s;]+;.*(?:Password|Pwd)=|Initial Catalog=|Integrated Security=)')
CRYPTO_RE = re.compile(
    r'(?i)(?:'
    r'new\s+(?:MD5|SHA1|DES|RC2|RC4|TripleDES)\w*\s*\('
    r'|Create(?:MD5|SHA1|DES|RC2|RC4)\w*\s*\('
    r'|HashAlgorithm\s*\.\s*Create\s*\(\s*["\'](?:MD5|SHA1)'
    r'|SymmetricAlgorithm\s*\.\s*Create\s*\(\s*["\'](?:DES|RC2|RC4)'
    r')'
)
ECB_RE = re.compile(r'(?i)CipherMode\.ECB')
IV_RE = re.compile(r'(?i)(?:(?:static|const|readonly).{0,20}\bIV\b|InitializationVector\s*=\s*new\s+byte)')
URL_RE = re.compile(r'https?://[A-Za-z0-9\.\-]+(?::\d+)?[A-Za-z0-9./_\-?=&%:]*')
JWT_RE = re.compile(r'(?i)(jwt|jsonwebtoken).{0,40}(secret|key|signing)')


def extract_utf16_strings(data: bytes, min_len: int = 4) -> set:
    """Extract UTF-16LE strings (C# strings are stored this way)."""
    result = set()
    # UTF-16LE: printable ASCII chars separated by \x00
    pattern = re.compile(rb'(?:[\x20-\x7E]\x00){' + str(min_len).encode() + rb',}')
    for m in pattern.finditer(data):
        try:
            s = m.group(0).decode('utf-16-le', errors='replace')
            # strip non-printables
            s = ''.join(c for c in s if c.isprintable() or c == ' ')
            if len(s) >= min_len:
                result.add(s)
        except Exception:
            pass
    return result


def extract_ascii_strings(data: bytes, min_len: int = 4) -> set:
    """Extract ASCII strings."""
    pattern = re.compile(b'[\x20-\x7E]{' + str(min_len).encode() + b',}')
    return {m.group(0).decode('ascii', errors='replace') for m in pattern.finditer(data)}


def extract_all_strings(path: Path) -> set:
    """Extract strings using all available methods."""
    try:
        raw = path.read_bytes()
    except Exception:
        return set()

    if len(raw) > 15 * 1024 * 1024:
        raw = raw[:15 * 1024 * 1024]

    strings = set()

    # 1. UTF-16 (C# default)
    strings |= extract_utf16_strings(raw, min_len=4)
    # 2. ASCII (fallback)
    strings |= extract_ascii_strings(raw, min_len=6)

    # 3. dnfile if available (best quality)
    if HAVE_DNFILE:
        try:
            pe = dnfile.dnPE(str(path))
            if pe.net and pe.net.user_strings:
                us = pe.net.user_strings
                # Try to iterate
                try:
                    for s in us:
                        if hasattr(s, 'value') and s.value:
                            strings.add(str(s.value))
                except (TypeError, AttributeError):
                    pass
                # Try .rows
                try:
                    for r in us.rows:
                        if hasattr(r, 'value') and r.value:
                            strings.add(str(r.value))
                except (AttributeError, TypeError):
                    pass
        except Exception:
            pass

    return strings


def is_valid_string(s: str) -> bool:
    """Accept any printable string."""
    if not s or len(s) < 4:
        return False
    # Must be mostly printable
    printable = sum(1 for c in s if c.isprintable() or c in ' \t')
    if printable / len(s) < 0.85:
        return False
    return True


class CodeAnalyzer(BaseAnalyzer):
    name = "code"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"dlls_analyzed": 0, "strings_extracted": 0, "skipped_framework": 0}
        seen_evidence = set()

        dll_files = list(ctx.app_root.rglob("*.dll"))
        if not dll_files:
            return findings

        for dll in dll_files:
            if dll.name in FRAMEWORK_DLLS:
                self.result["skipped_framework"] += 1
                continue

            strings = extract_all_strings(dll)
            if not strings:
                continue
            self.result["dlls_analyzed"] += 1
            self.result["strings_extracted"] += len(strings)

            for s in strings:
                if not is_valid_string(s):
                    continue

                ev_hash = hashlib.md5(s[:80].encode(errors='replace')).hexdigest()
                if ev_hash in seen_evidence:
                    continue

                # SQL
                if SQL_RE.search(s) and len(s) < 500:
                    seen_evidence.add(ev_hash)
                    findings.append(RawFinding(
                        rule_id="CODE_HARDCODED_SQL",
                        analyzer=self.name, category="Code Analysis",
                        severity="high", confidence="high",
                        title="Hardcoded SQL Query",
                        description="Raw SQL string in compiled code. Review for SQL injection.",
                        file_path=dll.name, evidence=s[:200],
                        cwe="CWE-89",
                        remediation="Use parameterized queries.",
                    ))
                    continue

                # DB Connection
                if DB_RE.search(s) and len(s) < 400:
                    seen_evidence.add(ev_hash)
                    findings.append(RawFinding(
                        rule_id="CODE_DB_CONNECTION",
                        analyzer=self.name, category="Code Analysis",
                        severity="critical", confidence="high",
                        title="Hardcoded Database Connection",
                        description="Database connection string embedded in code.",
                        file_path=dll.name, evidence=s[:200],
                        cwe="CWE-798",
                        remediation="Move to secure backend / Key Vault.",
                    ))
                    continue

                # Weak Crypto
                if CRYPTO_RE.search(s) and len(s) < 200:
                    seen_evidence.add(ev_hash)
                    findings.append(RawFinding(
                        rule_id="CODE_WEAK_CRYPTO",
                        analyzer=self.name, category="Cryptography",
                        severity="medium", confidence="medium",
                        title="Weak Crypto Algorithm",
                        description="MD5/SHA1/DES are cryptographically broken.",
                        file_path=dll.name, evidence=s[:150],
                        cwe="CWE-327",
                        remediation="Upgrade to SHA-256 / AES-GCM.",
                    ))
                    continue

                # ECB
                if ECB_RE.search(s):
                    seen_evidence.add(ev_hash)
                    findings.append(RawFinding(
                        rule_id="CODE_INSECURE_CIPHER",
                        analyzer=self.name, category="Cryptography",
                        severity="high", confidence="high",
                        title="Insecure ECB Cipher Mode",
                        description="ECB leaks plaintext patterns.",
                        file_path=dll.name, evidence=s[:150],
                        cwe="CWE-327",
                        remediation="Use CBC or GCM.",
                    ))
                    continue

                # Hardcoded IV
                if IV_RE.search(s) and len(s) < 250:
                    seen_evidence.add(ev_hash)
                    findings.append(RawFinding(
                        rule_id="CODE_HARDCODED_IV",
                        analyzer=self.name, category="Cryptography",
                        severity="high", confidence="medium",
                        title="Hardcoded IV",
                        description="Static IV defeats CBC encryption.",
                        file_path=dll.name, evidence=s[:150],
                        cwe="CWE-329",
                        remediation="Generate random IV per encryption.",
                    ))
                    continue

                # Sensitive URL
                url_match = URL_RE.search(s)
                if url_match and len(url_match.group(0)) > 10:
                    url = url_match.group(0)
                    if any(k in url.lower() for k in ["admin", "/internal", "staging", "dev.", "debug", "test."]):
                        seen_evidence.add(ev_hash)
                        findings.append(RawFinding(
                            rule_id="CODE_SENSITIVE_ENDPOINT",
                            analyzer=self.name, category="Code Analysis",
                            severity="medium", confidence="high",
                            title="Sensitive Endpoint in Code",
                            description="URL contains dev/staging/admin/internal keyword.",
                            file_path=dll.name, evidence=url,
                            cwe="CWE-200",
                            remediation="Remove dev endpoints from production.",
                        ))
                        continue

                # JWT Secret
                if JWT_RE.search(s) and len(s) < 300:
                    seen_evidence.add(ev_hash)
                    findings.append(RawFinding(
                        rule_id="CODE_JWT_SECRET",
                        analyzer=self.name, category="Code Analysis",
                        severity="critical", confidence="medium",
                        title="Potential JWT Secret",
                        description="JWT signing secret may be hardcoded.",
                        file_path=dll.name, evidence=s[:200],
                        cwe="CWE-798",
                        remediation="Store JWT secrets server-side only.",
                    ))

        return findings
