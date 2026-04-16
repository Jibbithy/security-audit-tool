import uuid
import requests
from datetime import datetime, timezone
from probes.base import BaseProbe, Finding, Severity

_TECH_KEYWORDS = ["Apache", "nginx", "IIS", "PHP", "ASP.NET", "Express", "Tomcat", "Jetty"]


class InventoryProbe(BaseProbe):
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        try:
            resp = requests.get(target_url, timeout=10, allow_redirects=True)
        except requests.RequestException:
            return []
        findings = []
        now = datetime.now(timezone.utc).isoformat()
        for header_name in ("Server", "X-Powered-By"):
            value = resp.headers.get(header_name, "")
            if any(tech in value for tech in _TECH_KEYWORDS):
                findings.append(Finding(
                    id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                    title=f"Server Technology Disclosed via {header_name} Header",
                    description=f"The {header_name} header discloses: '{value}', aiding attacker reconnaissance.",
                    severity=Severity.LOW, cvss_score=3.1,
                    cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200", owasp_category="A05:2021 - Security Misconfiguration",
                    component=f"{header_name} header",
                    remediation=f"Remove or obfuscate the {header_name} header in server configuration.",
                    detected_at=now,
                ))
        return findings
