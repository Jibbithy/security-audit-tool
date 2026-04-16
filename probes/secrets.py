import uuid, re
import requests
from datetime import datetime, timezone
from probes.base import BaseProbe, Finding, Severity

# (name, compiled_regex, cvss_score, cwe_id, remediation)
_PATTERNS = [
    (
        "Anthropic API Key",
        re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}"),
        9.1, "CWE-312",
        "Remove the API key from the response and rotate it immediately.",
    ),
    (
        "Generic API Key Assignment",
        re.compile(r"""(?i)(api[_\-]?key|apikey)\s*[=:]\s*["']([A-Za-z0-9\-_]{20,})["']"""),
        8.2, "CWE-312",
        "Remove the credential from the response. Store secrets server-side in environment variables.",
    ),
    (
        "Private RSA/EC Key",
        re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
        9.8, "CWE-312",
        "Remove the private key from the response immediately and rotate it.",
    ),
    (
        "AWS Access Key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        9.1, "CWE-312",
        "Rotate the AWS access key and remove it from all responses.",
    ),
    (
        "Stack Trace Disclosure",
        re.compile(r"(Traceback \(most recent call last\)|at\s+\w+\.\w+\([\w.]+:\d+\))"),
        5.3, "CWE-209",
        "Disable debug mode in production. Return generic error pages to users.",
    ),
    (
        "Directory Listing",
        re.compile(r"<title>Index of /"),
        5.3, "CWE-548",
        "Disable directory listing (e.g., Options -Indexes in Apache, autoindex off in nginx).",
    ),
]


class SecretsProbe(BaseProbe):
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        try:
            resp = requests.get(target_url, timeout=10, allow_redirects=True)
        except requests.RequestException:
            return []
        findings = []
        now = datetime.now(timezone.utc).isoformat()
        for name, pattern, cvss, cwe_id, remediation in _PATTERNS:
            if pattern.search(resp.text):
                severity = Severity.CRITICAL if cvss >= 9.0 else (Severity.HIGH if cvss >= 7.0 else Severity.MEDIUM)
                findings.append(Finding(
                    id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                    title=f"Exposed {name} in Response",
                    description=f"Pattern matching '{name}' found in the HTTP response body of {target_url}.",
                    severity=severity, cvss_score=cvss,
                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cwe_id=cwe_id, owasp_category="A02:2021 - Cryptographic Failures",
                    component="HTTP response body",
                    remediation=remediation, detected_at=now,
                ))
        return findings
