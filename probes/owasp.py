from probes.base import Finding
from probes.headers import HeadersProbe
from probes.tls import TLSProbe
from probes.secrets import SecretsProbe
from probes.auth import AuthProbe
from probes.inventory import InventoryProbe
from probes.cookies import CookiesProbe
from probes.cors import CORSProbe
from probes.email_security import EmailSecurityProbe
from probes.robots import RobotsProbe
from probes.js_libs import JSLibsProbe
from probes.http_methods import HTTPMethodsProbe
from probes.security_txt import SecurityTxtProbe
from probes.mixed_content import MixedContentProbe

_ALL_PROBES = [
    HeadersProbe,
    TLSProbe,
    SecretsProbe,
    AuthProbe,
    InventoryProbe,
    CookiesProbe,
    CORSProbe,
    EmailSecurityProbe,
    RobotsProbe,
    JSLibsProbe,
    HTTPMethodsProbe,
    SecurityTxtProbe,
    MixedContentProbe,
]

_SCOPE_PROBES: dict[str, list] = {
    "HEADERS_ONLY": [HeadersProbe],
    "TLS_ONLY":     [TLSProbe],
    "SECRETS":      [SecretsProbe],
    "AUTH":         [AuthProbe],
    "EMAIL":        [EmailSecurityProbe],
    "FULL_PASSIVE": _ALL_PROBES,
}


def run_full_passive_audit(target_url: str, run_id: str, scope: str = "FULL_PASSIVE") -> list[Finding]:
    probe_classes = _SCOPE_PROBES.get(scope, _SCOPE_PROBES["FULL_PASSIVE"])
    findings: list[Finding] = []
    for probe_cls in probe_classes:
        try:
            findings.extend(probe_cls().run(target_url, run_id))
        except Exception:
            pass  # one probe failure does not stop others
    return findings
