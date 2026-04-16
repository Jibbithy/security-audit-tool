from probes.base import Finding
from probes.headers import HeadersProbe
from probes.tls import TLSProbe
from probes.secrets import SecretsProbe
from probes.auth import AuthProbe
from probes.inventory import InventoryProbe

_SCOPE_PROBES: dict[str, list] = {
    "HEADERS_ONLY": [HeadersProbe],
    "TLS_ONLY": [TLSProbe],
    "SECRETS": [SecretsProbe],
    "AUTH": [AuthProbe],
    "FULL_PASSIVE": [HeadersProbe, TLSProbe, SecretsProbe, AuthProbe, InventoryProbe],
}


def run_full_passive_audit(target_url: str, run_id: str, scope: str = "FULL_PASSIVE") -> list[Finding]:
    probe_classes = _SCOPE_PROBES.get(scope, _SCOPE_PROBES["FULL_PASSIVE"])
    findings: list[Finding] = []
    for probe_cls in probe_classes:
        try:
            findings.extend(probe_cls().run(target_url, run_id))
        except Exception:
            pass  # One probe failure does not stop others
    return findings
