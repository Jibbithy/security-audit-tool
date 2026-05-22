import uuid
import re
import requests
from datetime import datetime, timezone
from probes.base import BaseProbe, Finding, Severity

# (library name, version regex, minimum safe version, cvss if outdated, cwe)
_LIBRARIES = [
    (
        "jQuery",
        re.compile(r"jquery[/-](\d+\.\d+\.?\d*)(?:\.min)?\.js", re.I),
        (3, 7, 0),
        6.1, "CWE-1104",
        "Upgrade to jQuery 3.7.0 or later. Older versions contain known XSS vulnerabilities.",
    ),
    (
        "Bootstrap",
        re.compile(r"bootstrap[/-](\d+\.\d+\.?\d*)(?:\.min)?\.(?:js|css)", re.I),
        (5, 3, 0),
        4.3, "CWE-1104",
        "Upgrade to Bootstrap 5.3.0 or later.",
    ),
    (
        "Angular",
        re.compile(r"angular[/-](\d+\.\d+\.?\d*)(?:\.min)?\.js", re.I),
        (17, 0, 0),
        6.5, "CWE-1104",
        "Upgrade to a supported Angular version (17+). Older versions may have XSS and prototype pollution vulnerabilities.",
    ),
    (
        "Vue.js",
        re.compile(r"vue[/-](\d+\.\d+\.?\d*)(?:\.min)?\.js", re.I),
        (3, 4, 0),
        4.3, "CWE-1104",
        "Upgrade to Vue 3.4.0 or later.",
    ),
    (
        "Lodash",
        re.compile(r"lodash[/-](\d+\.\d+\.?\d*)(?:\.min)?\.js", re.I),
        (4, 17, 21),
        6.5, "CWE-1104",
        "Upgrade to Lodash 4.17.21 or later to patch prototype pollution vulnerabilities.",
    ),
]


def _parse_version(s: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in s.split("."))
    except ValueError:
        return (0,)


class JSLibsProbe(BaseProbe):
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        try:
            resp = requests.get(target_url, timeout=10, allow_redirects=True)
        except requests.RequestException:
            return []

        findings = []
        now = datetime.now(timezone.utc).isoformat()
        text = resp.text

        for lib_name, pattern, min_version, cvss, cwe_id, remediation in _LIBRARIES:
            for match in pattern.finditer(text):
                version_str = match.group(1)
                version = _parse_version(version_str)
                if version < min_version:
                    min_ver_str = ".".join(str(v) for v in min_version)
                    findings.append(Finding(
                        id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                        title=f"Outdated JavaScript Library: {lib_name} {version_str}",
                        description=(
                            f"The page loads {lib_name} version {version_str}, which is below the minimum "
                            f"safe version ({min_ver_str}) and may contain known security vulnerabilities."
                        ),
                        severity=Severity.MEDIUM if cvss >= 4.0 else Severity.LOW,
                        cvss_score=cvss,
                        cvss_vector="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        cwe_id=cwe_id, owasp_category="A06:2021 - Vulnerable and Outdated Components",
                        component=f"{lib_name} {version_str}",
                        remediation=remediation,
                        detected_at=now,
                    ))
                    break  # one finding per library, first match wins
        return findings
