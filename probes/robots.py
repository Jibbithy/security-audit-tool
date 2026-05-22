import uuid
import re
import requests
from datetime import datetime, timezone
from urllib.parse import urljoin
from probes.base import BaseProbe, Finding, Severity

# Paths in robots.txt Disallow that suggest sensitive areas
_SENSITIVE_PATTERNS = re.compile(
    r"(?i)(admin|backup|config|database|db|dump|internal|private|secret|staging|test|upload|wp-admin|api)",
)


class RobotsProbe(BaseProbe):
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        findings = []
        now = datetime.now(timezone.utc).isoformat()
        base = target_url.rstrip("/")

        # ── robots.txt ────────────────────────────────────────────────
        try:
            resp = requests.get(f"{base}/robots.txt", timeout=8, allow_redirects=True)
            if resp.status_code == 200 and "text" in resp.headers.get("Content-Type", ""):
                sensitive_paths = []
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and _SENSITIVE_PATTERNS.search(path):
                            sensitive_paths.append(path)

                if sensitive_paths:
                    findings.append(Finding(
                        id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                        title="robots.txt Reveals Sensitive Paths",
                        description=(
                            f"robots.txt lists {len(sensitive_paths)} path(s) with sensitive-sounding names "
                            f"that may expose hidden functionality to attackers: {', '.join(sensitive_paths[:5])}"
                        ),
                        severity=Severity.LOW, cvss_score=3.1,
                        cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-200", owasp_category="A05:2021 - Security Misconfiguration",
                        component="robots.txt",
                        remediation=(
                            "Do not rely on robots.txt to hide sensitive paths — it is public. "
                            "Protect sensitive paths with authentication instead."
                        ),
                        detected_at=now,
                    ))
        except requests.RequestException:
            pass

        # ── sitemap.xml ───────────────────────────────────────────────
        try:
            resp = requests.get(f"{base}/sitemap.xml", timeout=8, allow_redirects=True)
            if resp.status_code == 200 and ("xml" in resp.headers.get("Content-Type", "") or resp.text.strip().startswith("<?xml")):
                url_count = resp.text.lower().count("<loc>")
                if url_count > 0:
                    findings.append(Finding(
                        id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                        title="sitemap.xml Exposes Full Site Structure",
                        description=(
                            f"sitemap.xml is publicly accessible and lists {url_count} URL(s), "
                            "giving attackers a complete map of the site's pages and structure."
                        ),
                        severity=Severity.INFO, cvss_score=2.0,
                        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-200", owasp_category="A05:2021 - Security Misconfiguration",
                        component="sitemap.xml",
                        remediation=(
                            "This is expected for public sites. If the sitemap includes private or staging URLs, "
                            "remove them. Consider blocking sitemap.xml for non-public sites."
                        ),
                        detected_at=now,
                    ))
        except requests.RequestException:
            pass

        return findings
