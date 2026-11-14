import sqlite3
import re
import json
from pathlib import Path
from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding


class LocalDataAnalyzer(BaseAnalyzer):
    name = "local_data"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"sqlite": [], "configs": [], "logs": []}

        # 1. SQLite databases
        for db_file in ctx.app_root.rglob("*.sqlite"):
            self._analyze_sqlite(db_file, ctx, findings)
        for db_file in ctx.app_root.rglob("*.db"):
            self._analyze_sqlite(db_file, ctx, findings)

        # 2. Log files
        for log in ctx.app_root.rglob("*.log"):
            try:
                size = log.stat().st_size
                rel = str(log.relative_to(ctx.app_root))
                self.result["logs"].append({"file": rel, "size": size})
                findings.append(RawFinding(
                    rule_id="LOCAL_LOG_FILE",
                    analyzer=self.name, category="Local Data",
                    severity="low", confidence="high",
                    title=f"Log file present: {rel}",
                    description="Log files may contain sensitive data.",
                    file_path=rel,
                    evidence=f"{size} bytes",
                    remediation="Remove log files from production builds.",
                ))
            except Exception:
                pass

        # 3. JSON config files with sensitive keys
        for json_file in ctx.app_root.rglob("*.json"):
            if json_file.stat().st_size > 500_000:
                continue
            try:
                text = json_file.read_text(errors="ignore")
                rel = str(json_file.relative_to(ctx.app_root))
                self._check_json(text, rel, json_file.name, findings)
            except Exception:
                pass

        return findings

    def _analyze_sqlite(self, db_path: Path, ctx, findings):
        try:
            size = db_path.stat().st_size
            rel = str(db_path.relative_to(ctx.app_root))
            self.result["sqlite"].append({"file": rel, "size": size})

            findings.append(RawFinding(
                rule_id="LOCAL_SQLITE_DB",
                analyzer=self.name, category="Local Data",
                severity="info", confidence="high",
                title=f"SQLite database: {rel}",
                description="Embedded SQLite database found. May contain PII or sensitive data.",
                file_path=rel,
                evidence=f"{size} bytes",
                remediation="Ensure no PII or credentials are shipped in the database. Use encryption-at-rest.",
            ))

            # Try to read tables
            try:
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [r[0] for r in cur.fetchall()]
                conn.close()

                if tables:
                    findings.append(RawFinding(
                        rule_id="LOCAL_SQLITE_TABLES",
                        analyzer=self.name, category="Local Data",
                        severity="medium", confidence="high",
                        title=f"SQLite tables in {rel}",
                        description=f"Database contains {len(tables)} tables: {', '.join(tables[:5])}",
                        file_path=rel,
                        evidence=f"Tables: {', '.join(tables[:10])}",
                        remediation="Verify no user data or credentials are shipped in schema/data.",
                    ))
            except Exception:
                pass
        except Exception:
            pass

    def _check_json(self, text, rel_path, name, findings):
        # Look for common sensitive keys in JSON
        sensitive_keys = ["password", "secret", "api_key", "apikey", "token", "auth",
                         "credential", "private_key", "access_key"]
        text_lower = text.lower()
        for key in sensitive_keys:
            if f'"{key}"' in text_lower:
                findings.append(RawFinding(
                    rule_id="LOCAL_CONFIG_SENSITIVE_KEY",
                    analyzer=self.name, category="Local Data",
                    severity="high", confidence="medium",
                    title=f"Sensitive key in config: {key}",
                    description=f"JSON config {rel_path} contains a '{key}' key.",
                    file_path=rel_path,
                    evidence=f"Key '{key}' present in {name}",
                    remediation="Never ship credentials in configuration files. Use secure backend or Keychain.",
                    cwe="CWE-798",
                ))
