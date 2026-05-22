import uuid
import requests
from datetime import datetime, timezone
from probes.base import BaseProbe, Finding, Severity

_DANGEROUS_METHODS = {"TRACE", "PUT", "DELETE", "CONNECT"}


class HTTPMethodsProbe(BaseProbe):
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        findings = []
        now = datetime.now(timezone.utc).isoformat()

        try:
            resp = requests.options(target_url, timeout=8)
        except requests.RequestException:
            return []

        allow_header = resp.headers.get("Allow", "") or resp.headers.get("Public", "")
        if not allow_header:
            return []

        enabled = {m.strip().upper() for m in allow_header.split(",")}
        dangerous_enabled = enabled & _DANGEROUS_METHODS

        if "TRACE" in dangerous_enabled:
            findings.append(Finding(
                id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                title="HTTP TRACE Method Enabled",
                description=(
                    "The TRACE method is enabled. It reflects the full HTTP request back to the caller, "
                    "which can be used to steal cookies via Cross-Site Tracing (XST) attacks."
                ),
                severity=Severity.MEDIUM, cvss_score=5.8,
                cvss_vector="AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
                cwe_id="CWE-749", owasp_category="A05:2021 - Security Misconfiguration",
                component="HTTP TRACE method",
                remediation="Disable TRACE in your web server config. In Apache: TraceEnable off. In nginx: it is disabled by default.",
                detected_at=now,
            ))

        for method in dangerous_enabled - {"TRACE"}:
            findings.append(Finding(
                id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                title=f"Potentially Dangerous HTTP Method Enabled: {method}",
                description=(
                    f"The {method} method is advertised as allowed by the server. "
                    "If not properly restricted, this could allow unauthorized data modification or deletion."
                ),
                severity=Severity.MEDIUM, cvss_score=5.3,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                cwe_id="CWE-749", owasp_category="A05:2021 - Security Misconfiguration",
                component=f"HTTP {method} method",
                remediation=f"Disable the {method} method unless explicitly required. Verify it is protected by authentication.",
                detected_at=now,
            ))

        return findings
