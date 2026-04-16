from unittest.mock import patch, MagicMock
import requests
from probes.headers import HeadersProbe
from probes.base import Severity


def mock_response(headers: dict, status_code=200, body="<html>clean</html>"):
    resp = MagicMock(spec=requests.Response)
    resp.headers = requests.structures.CaseInsensitiveDict(headers)
    resp.status_code = status_code
    resp.text = body
    resp.url = "https://example.com"
    return resp


def test_headers_probe_detects_missing_hsts():
    probe = HeadersProbe()
    with patch("probes.headers.requests.get") as mock_get:
        mock_get.return_value = mock_response({"Content-Type": "text/html"})
        findings = probe.run("https://example.com", "run1")
    assert any("HSTS" in f.title for f in findings)


def test_headers_probe_no_findings_when_all_present():
    probe = HeadersProbe()
    with patch("probes.headers.requests.get") as mock_get:
        mock_get.return_value = mock_response({
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        })
        findings = probe.run("https://example.com", "run1")
    assert findings == []


# --- TLS Probe ---

from probes.tls import TLSProbe


def test_tls_probe_expired_cert():
    probe = TLSProbe()
    fake_cert = {
        "notAfter": "Jan  1 00:00:00 2020 GMT",
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Test CA"),),),
    }
    with patch("probes.tls.ssl.create_default_context") as mock_ctx_cls, \
         patch("probes.tls.socket.create_connection") as mock_conn:
        mock_ctx = MagicMock()
        mock_ctx_cls.return_value = mock_ctx
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = fake_cert
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_conn.return_value.__enter__.return_value = MagicMock()
        findings = probe.run("https://example.com", "run1")
    assert any("Expired" in f.title for f in findings)


# --- Secrets Probe ---

from probes.secrets import SecretsProbe


def test_secrets_probe_detects_api_key_in_body():
    probe = SecretsProbe()
    with patch("probes.secrets.requests.get") as mock_get:
        mock_get.return_value = mock_response(
            {}, body='var config = { apiKey: "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789" };'
        )
        findings = probe.run("https://example.com", "run1")
    assert len(findings) >= 1
    assert any("Exposed" in f.title for f in findings)


def test_secrets_probe_no_findings_on_clean_response():
    probe = SecretsProbe()
    with patch("probes.secrets.requests.get") as mock_get:
        mock_get.return_value = mock_response({}, body="<html><body><h1>Hello World</h1></body></html>")
        findings = probe.run("https://example.com", "run1")
    assert findings == []


# --- Auth Probe ---

from probes.auth import AuthProbe


def test_auth_probe_detects_exposed_admin():
    probe = AuthProbe()

    def fake_get(url, **kwargs):
        r = MagicMock()
        r.status_code = 200 if "/admin" in url else 404
        r.url = url
        return r

    with patch("probes.auth.requests.get", side_effect=fake_get):
        findings = probe.run("https://example.com", "run1")
    assert any("/admin" in f.component for f in findings)


def test_auth_probe_no_findings_when_all_protected():
    probe = AuthProbe()

    def fake_get(url, **kwargs):
        r = MagicMock()
        r.status_code = 403
        r.url = url
        return r

    with patch("probes.auth.requests.get", side_effect=fake_get):
        findings = probe.run("https://example.com", "run1")
    assert findings == []


# --- OWASP Orchestrator ---

from probes.owasp import run_full_passive_audit


def test_owasp_orchestrator_full_passive_returns_list():
    with patch("probes.headers.requests.get") as mh, \
         patch("probes.secrets.requests.get") as ms, \
         patch("probes.auth.requests.get") as ma, \
         patch("probes.inventory.requests.get") as mi, \
         patch("probes.tls.ssl.create_default_context", side_effect=Exception("skip TLS")):
        mh.return_value = mock_response({"Content-Type": "text/html"})
        ms.return_value = mock_response({}, body="<html>clean</html>")
        ma_resp = MagicMock()
        ma_resp.status_code = 404
        ma_resp.url = "https://example.com"
        ma.return_value = ma_resp
        mi.return_value = mock_response({"Server": "Apache/2.4"})
        findings = run_full_passive_audit("https://example.com", "run1", scope="FULL_PASSIVE")
    assert isinstance(findings, list)
    assert len(findings) > 0  # header findings at minimum
