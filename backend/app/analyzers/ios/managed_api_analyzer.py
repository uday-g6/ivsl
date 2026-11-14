from pathlib import Path

import dnfile


MAX_ASSEMBLY_SIZE = 100 * 1024 * 1024
MAX_ASSEMBLIES = 2000
MAX_FINDINGS = 2000


API_RULES = [
    {
        "rule_id": "IOS-API-001",
        "category": "Legacy Cryptography",
        "namespace": "System.Security.Cryptography",
        "types": {
            "DES", "TripleDES", "RC2", "RC4",
            "MD5", "HMACMD5", "SHA1", "RIPEMD160"
        },
        "methods": None,
        "title": "Legacy cryptographic API reference",
        "description": (
            "The assembly references a legacy cryptographic algorithm. "
            "The reference alone does not prove that the algorithm is used "
            "for security-sensitive operations."
        ),
        "remediation": (
            "Review the algorithm's usage and replace it where appropriate "
            "with modern, approved cryptographic algorithms."
        )
    },
    {
        "rule_id": "IOS-API-002",
        "category": "Certificate Validation",
        "namespace": "System.Net",
        "types": {"ServicePointManager"},
        "methods": {
            "set_ServerCertificateValidationCallback",
            "get_ServerCertificateValidationCallback",
            "set_CheckCertificateRevocationList",
            "get_CheckCertificateRevocationList"
        },
        "title": "Certificate-validation configuration API reference",
        "description": (
            "The assembly references certificate-validation configuration. "
            "This does not establish that certificate validation is disabled."
        ),
        "remediation": (
            "Review certificate-chain validation, hostname validation "
            "and revocation-checking behavior."
        )
    },
    {
        "rule_id": "IOS-API-003",
        "category": "Native Interoperability",
        "namespace": "System.Runtime.InteropServices",
        "types": {"Marshal"},
        "methods": {"AllocHGlobal", "ReAllocHGlobal", "FreeHGlobal"},
        "title": "Native memory management API reference",
        "description": (
            "The assembly references unmanaged memory allocation or release "
            "APIs. Incorrect memory handling may introduce security issues."
        ),
        "remediation": (
            "Review allocation and release paths, buffer sizes and ownership "
            "of unmanaged memory."
        )
    },
    {
        "rule_id": "IOS-API-004",
        "category": "Process Execution",
        "namespace": "System.Diagnostics",
        "types": {"Process"},
        "methods": {"Start", "StartInfo"},
        "title": "Process execution API reference",
        "description": (
            "The assembly references a process execution API. "
            "This reference alone does not prove that an external process "
            "is launched."
        ),
        "remediation": (
            "Review command construction, input validation and execution "
            "permissions wherever this API is used."
        )
    },
    {
        "rule_id": "IOS-API-005",
        "category": "Reflection and Dynamic Loading",
        "namespace": "System.Reflection",
        "types": {"Assembly"},
        "methods": {"Load", "LoadFrom", "LoadFile", "UnsafeLoadFrom"},
        "title": "Dynamic assembly loading API reference",
        "description": (
            "The assembly references an API capable of loading assemblies "
            "dynamically. The reference alone does not prove unsafe loading."
        ),
        "remediation": (
            "Review assembly provenance, loading paths and trust boundaries."
        )
    },
    {
        "rule_id": "IOS-API-006",
        "category": "Serialization",
        "namespace": "System.Runtime.Serialization.Formatters.Binary",
        "types": {"BinaryFormatter"},
        "methods": {"Deserialize", "DeserializeMethodResponse"},
        "title": "Binary deserialization API reference",
        "description": (
            "The assembly references BinaryFormatter deserialization. "
            "Review whether untrusted input can reach this operation."
        ),
        "remediation": (
            "Avoid unsafe deserialization of untrusted data and use safer "
            "serialization formats."
        )
    },
    {
        "rule_id": "IOS-API-007",
        "category": "Sensitive File Operations",
        "namespace": "System.IO",
        "types": {"File", "FileInfo", "FileStream", "Directory"},
        "methods": {
            "ReadAllText", "ReadAllBytes", "WriteAllText",
            "WriteAllBytes", "OpenRead", "OpenWrite",
            "Create", "Delete", "Move", "Copy",
            "GetFiles", "GetDirectories"
        },
        "title": "File-system operation API reference",
        "description": (
            "The assembly references file-system operations. "
            "Review access controls, path handling and sensitive-data exposure."
        ),
        "remediation": (
            "Validate paths, enforce appropriate access controls and "
            "protect sensitive files."
        )
    },
    {
        "rule_id": "IOS-API-008",
        "category": "Network Communication",
        "namespace": "System.Net",
        "types": {"WebRequest", "HttpWebRequest", "WebClient"},
        "methods": {
            "Create", "GetResponse", "GetRequestStream",
            "DownloadString", "UploadString"
        },
        "title": "Network communication API reference",
        "description": (
            "The assembly references network communication APIs. "
            "The reference alone does not establish insecure communication."
        ),
        "remediation": (
            "Review transport security, endpoint validation and "
            "handling of sensitive request and response data."
        )
    }
]


def get_value(item):
    if item is None:
        return None

    value = getattr(item, "value", item)

    if isinstance(value, bytes):
        return value.hex()

    return str(value)


def make_finding(rule, assembly, namespace, type_name,
                 method_name, token, signature):

    return {
        "rule_id": rule["rule_id"],
        "title": rule["title"],
        "severity": "INFO",
        "category": rule["category"],
        "description": rule["description"],
        "evidence": {
            "assembly": assembly,
            "namespace": namespace,
            "type": type_name,
            "method": method_name,
            "metadata_token": token,
            "signature_hex": signature
        },
        "remediation": rule["remediation"]
    }


def resolve_member_parent(member):
    parent = getattr(member, "Class", None)
    row = getattr(parent, "row", None)

    if row is None:
        return "", "", "Unknown"

    namespace = get_value(
        getattr(row, "TypeNamespace", None)
    ) or ""

    type_name = (
        get_value(getattr(row, "TypeName", None))
        or get_value(getattr(row, "Name", None))
        or ""
    )

    table = getattr(parent, "table", None)
    table_name = type(table).__name__ if table is not None else "Unknown"

    return namespace, type_name, table_name


def match_api(namespace, type_name, method_name):
    for rule in API_RULES:
        if not namespace.startswith(rule["namespace"]):
            continue

        if type_name not in rule["types"]:
            continue

        if rule["methods"] is not None:
            if method_name not in rule["methods"]:
                continue

        return rule

    return None


def inspect_managed_api_references(path: Path, root: Path):
    findings = []
    references = []
    errors = []

    pe = None

    try:
        pe = dnfile.dnPE(str(path))

        if pe is None or getattr(pe, "net", None) is None:
            return {
                "status": "not_managed",
                "references_scanned": 0,
                "findings": [],
                "references": []
            }

        tables = pe.net.mdtables

        member_table = getattr(tables, "MemberRef", None)
        rows = member_table.rows if member_table is not None else []

        assembly_rows = getattr(tables, "Assembly", None)
        assembly_rows = assembly_rows.rows if assembly_rows else []

        assembly_name = path.name

        if assembly_rows:
            assembly_name = (
                get_value(assembly_rows[0].Name) or path.name
            )

        seen = set()

        for index, member in enumerate(rows or [], start=1):
            namespace, type_name, parent_table = resolve_member_parent(member)

            method_name = get_value(
                getattr(member, "Name", None)
            ) or ""

            signature = get_value(
                getattr(member, "Signature", None)
            ) or ""

            token = f"0x0A{index:06X}"

            reference = {
                "namespace": namespace,
                "type": type_name,
                "method": method_name,
                "parent_table": parent_table,
                "metadata_token": token
            }

            references.append(reference)

            rule = match_api(namespace, type_name, method_name)

            if rule is None:
                continue

            dedupe_key = (
                rule["rule_id"],
                namespace,
                type_name,
                method_name
            )

            if dedupe_key in seen:
                continue

            seen.add(dedupe_key)

            findings.append(
                make_finding(
                    rule,
                    assembly_name,
                    namespace,
                    type_name,
                    method_name,
                    token,
                    signature
                )
            )

    except Exception as exc:
        errors.append(type(exc).__name__)

    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass

    return {
        "status": "error" if errors else "completed",
        "references_scanned": len(references),
        "references": references,
        "findings": findings,
        "errors": errors
    }


def analyze_managed_api_references(app_path: str) -> dict:
    root = Path(app_path).resolve()

    if not root.is_dir():
        return {
            "status": "error",
            "error": "Application directory not found",
            "assemblies_scanned": 0,
            "findings": []
        }

    assemblies_scanned = 0
    managed_assemblies = 0
    skipped_files = 0
    findings = []
    truncated = False

    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue

        if path.suffix.lower() not in {".dll", ".exe"}:
            continue

        if assemblies_scanned >= MAX_ASSEMBLIES:
            skipped_files += 1
            truncated = True
            continue

        try:
            size = path.stat().st_size

            if size == 0 or size > MAX_ASSEMBLY_SIZE:
                skipped_files += 1
                continue

        except OSError:
            skipped_files += 1
            continue

        assemblies_scanned += 1

        result = inspect_managed_api_references(path, root)

        if result["status"] == "not_managed":
            continue

        if result["status"] == "completed":
            managed_assemblies += 1

        for finding in result["findings"]:
            if len(findings) >= MAX_FINDINGS:
                truncated = True
                break

            finding["evidence"]["file"] = str(
                path.relative_to(root)
            )

            findings.append(finding)

        if len(findings) >= MAX_FINDINGS:
            truncated = True
            break

    return {
        "status": "completed",
        "analysis_type": "static",
        "assemblies_scanned": assemblies_scanned,
        "managed_assemblies_found": managed_assemblies,
        "skipped_files": skipped_files,
        "findings_count": len(findings),
        "findings_truncated": truncated,
        "findings": findings
    }
