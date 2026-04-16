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
