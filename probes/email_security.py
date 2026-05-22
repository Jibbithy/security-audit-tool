import uuid
import dns.resolver
from datetime import datetime, timezone
from urllib.parse import urlparse
from probes.base import BaseProbe, Finding, Severity


def _txt_records(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=8)
        return [b.decode() for rdata in answers for b in rdata.strings]
    except Exception:
        return []


class EmailSecurityProbe(BaseProbe):
    def run(self, target_url: str, run_id: str) -> list[Finding]:
        domain = urlparse(target_url).hostname or ""
        if not domain:
            return []

        findings = []
        now = datetime.now(timezone.utc).isoformat()

        # ── SPF ────────────────────────────────────────────────────────
        txt = _txt_records(domain)
        spf_records = [r for r in txt if r.startswith("v=spf1")]
        if not spf_records:
            findings.append(Finding(
                id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                title="Missing SPF DNS Record",
                description=(
                    f"No SPF record found for {domain}. Anyone can send email that appears to come "
                    "from your domain, enabling phishing and spoofing attacks against your users."
                ),
                severity=Severity.MEDIUM, cvss_score=5.3,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                cwe_id="CWE-183", owasp_category="A05:2021 - Security Misconfiguration",
                component=f"DNS TXT record for {domain}",
                remediation=(
                    f'Add an SPF TXT record to your DNS: "{domain} TXT v=spf1 include:_spf.yourmailprovider.com ~all"'
                ),
                detected_at=now,
            ))
        else:
            spf = spf_records[0]
            if spf.endswith("+all") or spf.endswith(" all") and "~" not in spf and "-" not in spf:
                findings.append(Finding(
                    id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                    title="Weak SPF Record (+all or neutral policy)",
                    description=(
                        f"The SPF record for {domain} uses a permissive policy that still allows "
                        "anyone to send email as your domain."
                    ),
                    severity=Severity.MEDIUM, cvss_score=4.3,
                    cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    cwe_id="CWE-183", owasp_category="A05:2021 - Security Misconfiguration",
                    component=f"SPF record for {domain}",
                    remediation="Change your SPF record to end with ~all (softfail) or -all (hardfail).",
                    detected_at=now,
                ))

        # ── DMARC ─────────────────────────────────────────────────────
        dmarc_txt = _txt_records(f"_dmarc.{domain}")
        dmarc_records = [r for r in dmarc_txt if r.startswith("v=DMARC1")]
        if not dmarc_records:
            findings.append(Finding(
                id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                title="Missing DMARC DNS Record",
                description=(
                    f"No DMARC record found for {domain}. Without DMARC, receiving mail servers have "
                    "no instructions on what to do with spoofed emails from your domain — they may deliver them."
                ),
                severity=Severity.MEDIUM, cvss_score=5.3,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                cwe_id="CWE-183", owasp_category="A05:2021 - Security Misconfiguration",
                component=f"DNS TXT record for _dmarc.{domain}",
                remediation=(
                    f'Add a DMARC TXT record: "_dmarc.{domain} TXT v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"'
                ),
                detected_at=now,
            ))
        else:
            dmarc = dmarc_records[0]
            if "p=none" in dmarc:
                findings.append(Finding(
                    id=str(uuid.uuid4()), run_id=run_id, target_url=target_url,
                    title="DMARC Policy Set to None (No Enforcement)",
                    description=(
                        f"The DMARC record for {domain} uses p=none, which means spoofed emails "
                        "are still delivered — the policy only monitors, it does not block."
                    ),
                    severity=Severity.LOW, cvss_score=3.7,
                    cvss_vector="AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    cwe_id="CWE-183", owasp_category="A05:2021 - Security Misconfiguration",
                    component=f"DMARC policy for {domain}",
                    remediation="Upgrade your DMARC policy from p=none to p=quarantine or p=reject.",
                    detected_at=now,
                ))
        return findings
