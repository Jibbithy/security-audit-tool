import uuid
import requests
from datetime import datetime, timezone
from probes.base import BaseProbe, Finding, Severity


class CORSProbe(BaseProbe):
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        try:
            resp = requests.get(
                target_url,
                timeout=10,
                allow_redirects=True,
                headers={"Origin": "https://evil-attacker.com"},
            )
        except requests.RequestException:
            return []

        findings = []
        now = datetime.now(timezone.utc).isoformat()
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            findings.append(Finding(
                id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                title="Permissive CORS Policy (Wildcard Origin)",
                description=(
                    "The server returns Access-Control-Allow-Origin: * meaning any website "
                    "can read responses from this origin via a browser fetch/XHR request."
                ),
                severity=Severity.MEDIUM, cvss_score=5.3,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-942", owasp_category="A05:2021 - Security Misconfiguration",
                component="Access-Control-Allow-Origin header",
                remediation=(
                    "Restrict CORS to trusted origins. Replace * with an explicit allowlist "
                    "of domains, e.g. Access-Control-Allow-Origin: https://yourdomain.com"
                ),
                detected_at=now,
            ))
        elif acao == "https://evil-attacker.com":
            # Server reflected the attacker origin back — dynamic reflection without validation
            severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
            cvss = 8.1 if acac == "true" else 6.5
            findings.append(Finding(
                id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                title="CORS Origin Reflection" + (" with Credentials" if acac == "true" else ""),
                description=(
                    "The server reflects any Origin header back in Access-Control-Allow-Origin "
                    "without validating it" +
                    (", and also allows credentials (cookies/auth headers) to be included. "
                     "This allows any website to make authenticated cross-origin requests on behalf of users."
                     if acac == "true" else ".")
                ),
                severity=severity, cvss_score=cvss,
                cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                cwe_id="CWE-942", owasp_category="A01:2021 - Broken Access Control",
                component="Access-Control-Allow-Origin header",
                remediation=(
                    "Validate the Origin header against an explicit allowlist before reflecting it. "
                    "Never combine a dynamic reflected origin with Access-Control-Allow-Credentials: true."
                ),
                detected_at=now,
            ))
        return findings
