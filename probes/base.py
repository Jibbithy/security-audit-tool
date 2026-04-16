from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    id: str
    run_id: str
    target_url: str
    title: str
    description: str
    severity: Severity
    cvss_score: float
    cvss_vector: str
    cwe_id: str
    owasp_category: str
    component: str
    remediation: str
    detected_at: str  # ISO 8601


@dataclass
class AuditTarget:
    url: str
    scope: str   # FULL_PASSIVE, HEADERS_ONLY, TLS_ONLY, SECRETS, AUTH
    priority: str  # HIGH, MEDIUM, LOW
    row_index: int  # Google Sheet row for writing results back


@dataclass
class RunDelta:
    new_findings: list[Finding]
    fixed_finding_ids: list[str]   # IDs of prior findings now absent
    regressed_findings: list[Finding]  # Same CWE, higher CVSS than prior run


class BaseProbe(ABC):
    """Abstract base for all passive security probes."""

    @abstractmethod
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        """Run probe against target_url. Returns list of findings."""
        ...
