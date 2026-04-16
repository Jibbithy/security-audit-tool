import uuid, ssl, socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from probes.base import BaseProbe, Finding, Severity


def _parse_cert_date(date_str: str) -> datetime:
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


class TLSProbe(BaseProbe):
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        parsed = urlparse(target_url)
        if parsed.scheme != "https":
            return []
        hostname = parsed.hostname
        port = parsed.port or 443
        findings = []
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
        except ssl.SSLCertVerificationError:
            findings.append(Finding(
                id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                title="Invalid or Self-Signed TLS Certificate",
                description="The TLS certificate could not be verified. It may be self-signed or from an untrusted CA.",
                severity=Severity.HIGH, cvss_score=6.8,
                cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-295", owasp_category="A02:2021 - Cryptographic Failures",
                component="TLS Certificate",
                remediation="Install a certificate from a trusted CA (e.g., Let's Encrypt).",
                detected_at=now_iso,
            ))
            return findings
        except Exception:
            return findings

        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            try:
                not_after = _parse_cert_date(not_after_str)
                days_left = (not_after - now).days
                if not_after < now:
                    findings.append(Finding(
                        id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                        title="Expired TLS Certificate",
                        description=f"The TLS certificate expired on {not_after_str}.",
                        severity=Severity.HIGH, cvss_score=7.5,
                        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-295", owasp_category="A02:2021 - Cryptographic Failures",
                        component="TLS Certificate expiry",
                        remediation="Renew the TLS certificate immediately.",
                        detected_at=now_iso,
                    ))
                elif days_left < 30:
                    findings.append(Finding(
                        id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                        title="TLS Certificate Expiring Soon",
                        description=f"Certificate expires in {days_left} days ({not_after_str}).",
                        severity=Severity.MEDIUM, cvss_score=4.0,
                        cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        cwe_id="CWE-295", owasp_category="A02:2021 - Cryptographic Failures",
                        component="TLS Certificate expiry",
                        remediation="Renew the certificate before it expires.",
                        detected_at=now_iso,
                    ))
            except ValueError:
                pass

        if tls_version in ("TLSv1", "TLSv1.1"):
            findings.append(Finding(
                id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                title=f"Outdated TLS Protocol: {tls_version}",
                description=f"Server negotiated {tls_version}, which is deprecated and insecure.",
                severity=Severity.HIGH, cvss_score=7.4,
                cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-326", owasp_category="A02:2021 - Cryptographic Failures",
                component=f"TLS protocol version ({tls_version})",
                remediation="Disable TLS 1.0 and 1.1. Enforce TLS 1.2 minimum, prefer TLS 1.3.",
                detected_at=now_iso,
            ))
        return findings
