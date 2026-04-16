from google.oauth2 import service_account
from googleapiclient.discovery import build
from probes.base import AuditTarget, Finding
from datetime import datetime, timezone

_SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]
_TARGETS_RANGE = "Targets!A2:G1000"


class SheetsSync:
    def __init__(self, creds_path: str, sheet_id: str):
        self.sheet_id = sheet_id
        creds = service_account.Credentials.from_service_account_file(
            creds_path, scopes=_SCOPES
        )
        self._service = build("sheets", "v4", credentials=creds)

    def read_targets(self) -> list[AuditTarget]:
        result = (
            self._service.spreadsheets()
            .values()
            .get(spreadsheetId=self.sheet_id, range=_TARGETS_RANGE)
            .execute()
        )
        rows = result.get("values", [])
        targets = []
        for i, row in enumerate(rows):
            if not row or not row[0].strip():
                continue
            url = row[0].strip()
            scope = row[1].strip() if len(row) > 1 else "FULL_PASSIVE"
            if scope not in ("FULL_PASSIVE", "HEADERS_ONLY", "TLS_ONLY", "SECRETS", "AUTH"):
                scope = "FULL_PASSIVE"
            targets.append(AuditTarget(url=url, scope=scope, priority="HIGH", row_index=i + 2))
        return targets

    def write_results(self, target: AuditTarget, findings: list[Finding], trend: str = ""):
        max_cvss = max((f.cvss_score for f in findings), default=0.0)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        values = [["COMPLETED", now, len(findings), round(max_cvss, 1), trend]]
        self._service.spreadsheets().values().update(
            spreadsheetId=self.sheet_id,
            range=f"Targets!C{target.row_index}:G{target.row_index}",
            valueInputOption="RAW",
            body={"values": values},
        ).execute()
