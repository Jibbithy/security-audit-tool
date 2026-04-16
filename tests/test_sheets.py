from unittest.mock import patch, MagicMock
from probes.base import AuditTarget, Finding, Severity
from datetime import datetime, timezone
import uuid


def test_read_targets_parses_rows():
    with patch("sheets.build") as mock_build, \
         patch("sheets.service_account.Credentials.from_service_account_file"):
        mock_service = MagicMock()
        mock_build.return_value = mock_service
        mock_service.spreadsheets().values().get().execute.return_value = {
            "values": [
                ["https://example.com", "FULL_PASSIVE", "PENDING", "", "", "", ""],
                ["https://test.com", "HEADERS_ONLY", "PENDING", "", "", "", ""],
            ]
        }
        from sheets import SheetsSync
        ss = SheetsSync.__new__(SheetsSync)
        ss.sheet_id = "sheet123"
        ss._service = mock_service
        targets = ss.read_targets()
    assert len(targets) == 2
    assert targets[0].url == "https://example.com"
    assert targets[0].scope == "FULL_PASSIVE"
    assert targets[1].url == "https://test.com"


def test_read_targets_skips_empty_rows():
    with patch("sheets.build") as mock_build, \
         patch("sheets.service_account.Credentials.from_service_account_file"):
        mock_service = MagicMock()
        mock_build.return_value = mock_service
        mock_service.spreadsheets().values().get().execute.return_value = {
            "values": [
                ["https://example.com", "FULL_PASSIVE"],
                ["", ""],   # empty — should be skipped
            ]
        }
        from sheets import SheetsSync
        ss = SheetsSync.__new__(SheetsSync)
        ss.sheet_id = "sheet123"
        ss._service = mock_service
        targets = ss.read_targets()
    assert len(targets) == 1
