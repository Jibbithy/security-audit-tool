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
