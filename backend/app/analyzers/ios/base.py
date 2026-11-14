from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

@dataclass
class RawFinding:
    rule_id: str
    analyzer: str
    category: str
    severity: str        # critical|high|medium|low|info
    confidence: str      # high|medium|low
    title: str
    description: str = ""
    file_path: Optional[str] = None
    line: Optional[int] = None
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    cwe: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AnalyzerContext:
    scan_id: str
    app_root: Path        # path to Payload/<App>.app
    executable_path: Optional[Path]
    info_plist: Dict[str, Any]
    all_files: List[Path]

class BaseAnalyzer(ABC):
    name: str = "base"
    @abstractmethod
    def run(self, ctx: AnalyzerContext) -> List[RawFinding]:
        ...