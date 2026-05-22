import uuid
import re
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse
from probes.base import BaseProbe, Finding, Severity

# Match src/href/action/url() values that use http:// explicitly
_HTTP_RESOURCE = re.compile(r"""(?:src|href|action|url)\s*[=(]['"]http://[^'">\s]+""", re.I)


class MixedContentProbe(BaseProbe):
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        if not target_url.startswith("https://"):
            return []  # only relevant for HTTPS pages

        try:
            resp = requests.get(target_url, timeout=10, allow_redirects=True)
        except requests.RequestException:
            return []

        if "text/html" not in resp.headers.get("Content-Type", ""):
            return []

        matches = _HTTP_RESOURCE.findall(resp.text)
        if not matches:
            return []

        now = datetime.now(timezone.utc).isoformat()
        examples = list({m.split("http://")[1].split("/")[0] for m in matches[:5]})

        return [Finding(
            id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
            title="Mixed Content: HTTP Resources on HTTPS Page",
            description=(
                f"The HTTPS page loads {len(matches)} resource(s) over plain HTTP "
                f"(e.g. from: {', '.join(examples)}). Browsers may block these resources "
                "and users on the same network can intercept or modify them."
            ),
            severity=Severity.MEDIUM, cvss_score=4.3,
            cvss_vector="AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            cwe_id="CWE-319", owasp_category="A02:2021 - Cryptographic Failures",
            component="HTTP resources embedded in HTTPS page",
            remediation=(
                "Change all embedded resource URLs from http:// to https://. "
                "Use a Content-Security-Policy with upgrade-insecure-requests to catch future cases."
            ),
            detected_at=now,
        )]
