from google.oauth2 import service_account
from googleapiclient.discovery import build
from probes.base import AuditTarget, Finding, Severity
from datetime import datetime, timezone, UTC

_SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]
_TARGETS_RANGE = "Targets!A2:G1000"
_RESULTS_TAB = "Results"

# Each audit category: display name, plain-English description, and which title keywords belong to it
_CATEGORIES = [
    (
        "Security Headers",
        "Checks whether your site tells browsers to enforce safety rules (e.g. only load over HTTPS, block framing, restrict scripts).",
        ["HSTS", "X-Frame", "X-Content-Type", "Content-Security-Policy", "Referrer-Policy", "Permissions-Policy"],
    ),
    (
        "HTTPS & Certificate",
        "Checks whether your SSL/TLS certificate is valid, not expired, and using a modern encryption protocol.",
        ["TLS", "Certificate", "SSL", "Expired", "Protocol"],
    ),
    (
        "Cookie Security",
        "Checks whether your site's cookies are protected against theft and cross-site attacks.",
        ["Cookie Missing", "Cookie"],
    ),
    (
        "CORS Policy",
        "Checks whether your site restricts which other websites can read its responses in a browser.",
        ["CORS", "Origin"],
    ),
    (
        "Email Security",
        "Checks DNS records that protect your domain from being used to send fake/phishing emails.",
        ["SPF", "DMARC", "Email"],
    ),
    (
        "Exposed Secrets",
        "Checks whether API keys, passwords, private keys, or error stack traces are accidentally visible in your site's responses.",
        ["Exposed", "Stack Trace", "Directory Listing", "API Key", "Private Key", "AWS"],
    ),
    (
        "Access Control",
        "Checks whether admin panels, config files, API docs, or backup files are publicly accessible without a login.",
        ["Unauthenticated", "Sensitive Path", "admin"],
    ),
    (
        "Outdated Libraries",
        "Checks whether the page loads old JavaScript libraries with known security vulnerabilities.",
        ["Outdated JavaScript", "jQuery", "Bootstrap", "Angular", "Vue", "Lodash"],
    ),
    (
        "HTTP Methods",
        "Checks whether dangerous server commands (TRACE, PUT, DELETE) are left switched on.",
        ["HTTP TRACE", "HTTP Method", "Dangerous HTTP"],
    ),
    (
        "Mixed Content",
        "Checks whether your HTTPS site loads any resources (images, scripts) over unencrypted HTTP.",
        ["Mixed Content"],
    ),
    (
        "Disclosure & Hygiene",
        "Checks for information leakage and missing security best-practice files.",
        ["robots.txt", "sitemap.xml", "Server Technology", "Disclosed", "X-Powered-By", "security.txt"],
    ),
]

# Severity → plain-English risk label
_RISK_LABELS = {
    Severity.CRITICAL: "🔴 Critical",
    Severity.HIGH:     "🟠 High",
    Severity.MEDIUM:   "🟡 Medium",
    Severity.LOW:      "🟢 Low",
    Severity.INFO:     "⚪ Info",
}

# Severity → background colour (RGB 0–1)
_SEV_COLORS = {
    Severity.CRITICAL: {"red": 0.96, "green": 0.80, "blue": 0.80},
    Severity.HIGH:     {"red": 0.99, "green": 0.88, "blue": 0.78},
    Severity.MEDIUM:   {"red": 1.00, "green": 0.96, "blue": 0.78},
    Severity.LOW:      {"red": 0.85, "green": 0.94, "blue": 0.85},
    Severity.INFO:     {"red": 0.95, "green": 0.95, "blue": 0.95},
}
_CLEAR_COLOR   = {"red": 0.85, "green": 0.94, "blue": 0.85}   # green — all clear
_HEADER_COLOR  = {"red": 0.102, "green": 0.102, "blue": 0.18}  # dark navy
_SECTION_COLOR = {"red": 0.18, "green": 0.22, "blue": 0.36}    # mid navy


def _categorise(finding: Finding) -> str:
    for name, _, keywords in _CATEGORIES:
        if any(kw.lower() in finding.title.lower() for kw in keywords):
            return name
    return "Other"


class SheetsSync:
    def __init__(self, creds_path: str, sheet_id: str):
        self.sheet_id = sheet_id
        creds = service_account.Credentials.from_service_account_file(
            creds_path, scopes=_SCOPES
        )
        self._service = build("sheets", "v4", credentials=creds)

    # ------------------------------------------------------------------
    # Read targets
    # ------------------------------------------------------------------

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
            if not (url.startswith("http://") or url.startswith("https://")):
                if "." not in url:
                    continue
                url = "https://" + url
            scope = row[1].strip() if len(row) > 1 else "FULL_PASSIVE"
            if scope not in ("FULL_PASSIVE", "HEADERS_ONLY", "TLS_ONLY", "SECRETS", "AUTH"):
                scope = "FULL_PASSIVE"
            targets.append(AuditTarget(url=url, scope=scope, priority="HIGH", row_index=i + 2))
        return targets

    # ------------------------------------------------------------------
    # Write summary back to Targets tab
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Write plain-English Results tab
    # ------------------------------------------------------------------

    def write_results_detail(self, run_id: str, url: str, findings: list[Finding], started_at: str):
        """Accumulate one audit run. Call write_all_results_detail() to flush everything to sheet."""
        if not hasattr(self, "_pending_results"):
            self._pending_results: list[tuple[str, str, list[Finding], str]] = []
        # Replace any existing entry for this exact run
        self._pending_results = [(r, u, f, d) for r, u, f, d in self._pending_results if r != run_id]
        self._pending_results.append((run_id, url, findings, started_at))

    def write_all_results_detail(self):
        """Write every accumulated site to the Results tab, separated by a black divider row."""
        if not hasattr(self, "_pending_results") or not self._pending_results:
            return

        tab_id = self._get_or_create_tab(_RESULTS_TAB)
        rows: list[list[str]] = []
        format_requests: list[dict] = []

        # ── Column headers (row 0, frozen) ────────────────────────────
        rows.append([
            "Website", "Check Category", "What Was Checked",
            "Issue Found", "Plain-English Explanation",
            "Risk Level", "How to Fix It", "Date Audited",
        ])
        format_requests.append({
            "repeatCell": {
                "range": {"sheetId": tab_id, "startRowIndex": 0, "endRowIndex": 1},
                "cell": {"userEnteredFormat": {
                    "backgroundColor": _SECTION_COLOR,
                    "textFormat": {"foregroundColor": {"red": 1, "green": 1, "blue": 1}, "bold": True},
                }},
                "fields": "userEnteredFormat(backgroundColor,textFormat)",
            }
        })

        # ── One section per audit run, most-recent first ──────────────
        for run_id, url, findings, audit_date in self._pending_results:
            # Black divider / site banner
            divider_idx = len(rows)
            rows.append([f"  {url}   —   Audited {audit_date}   (run {run_id[:8]})", "", "", "", "", "", "", ""])
            format_requests.append({
                "repeatCell": {
                    "range": {"sheetId": tab_id, "startRowIndex": divider_idx, "endRowIndex": divider_idx + 1},
                    "cell": {"userEnteredFormat": {
                        "backgroundColor": {"red": 0.05, "green": 0.05, "blue": 0.05},
                        "textFormat": {
                            "foregroundColor": {"red": 1, "green": 1, "blue": 1},
                            "bold": True,
                            "fontSize": 11,
                        },
                        "padding": {"top": 6, "bottom": 6, "left": 10},
                    }},
                    "fields": "userEnteredFormat(backgroundColor,textFormat,padding)",
                }
            })

            # Group findings by category
            by_cat: dict[str, list[Finding]] = {name: [] for name, _, _ in _CATEGORIES}
            by_cat["Other"] = []
            for f in findings:
                by_cat[_categorise(f)].append(f)

            # One row per category (all-clear or individual findings)
            for cat_name, cat_desc, _ in _CATEGORIES:
                cat_findings = by_cat.get(cat_name, [])
                if not cat_findings:
                    row_idx = len(rows)
                    rows.append([
                        url, cat_name, cat_desc,
                        "✓ Nothing found", "No issues detected in this area.",
                        "✅ All Clear", "No action needed.", audit_date,
                    ])
                    format_requests.append(_row_color(tab_id, row_idx, _CLEAR_COLOR))
                else:
                    for f in sorted(cat_findings, key=lambda x: x.cvss_score, reverse=True):
                        row_idx = len(rows)
                        rows.append([
                            url, cat_name, cat_desc,
                            f.title,
                            _plain_english(f),
                            _RISK_LABELS[f.severity],
                            f.remediation,
                            _fmt_ts(f.detected_at),
                        ])
                        format_requests.append(_row_color(tab_id, row_idx, _SEV_COLORS[f.severity]))

        # ── Clear and write ────────────────────────────────────────────
        self._service.spreadsheets().values().clear(
            spreadsheetId=self.sheet_id, range=f"{_RESULTS_TAB}!A1:Z5000"
        ).execute()
        self._service.spreadsheets().values().update(
            spreadsheetId=self.sheet_id,
            range=f"{_RESULTS_TAB}!A1",
            valueInputOption="RAW",
            body={"values": rows},
        ).execute()

        # ── Formatting ─────────────────────────────────────────────────
        base_requests = [
            # Freeze header row
            {
                "updateSheetProperties": {
                    "properties": {"sheetId": tab_id, "gridProperties": {"frozenRowCount": 1}},
                    "fields": "gridProperties.frozenRowCount",
                }
            },
            # Wrap all text
            {
                "repeatCell": {
                    "range": {"sheetId": tab_id},
                    "cell": {"userEnteredFormat": {"wrapStrategy": "WRAP"}},
                    "fields": "userEnteredFormat.wrapStrategy",
                }
            },
            # Column widths: A=200, B=160, C=260, D=220, E=300, F=120, G=300, H=170
            *[
                {"updateDimensionProperties": {
                    "range": {"sheetId": tab_id, "dimension": "COLUMNS", "startIndex": i, "endIndex": i + 1},
                    "properties": {"pixelSize": w},
                    "fields": "pixelSize",
                }}
                for i, w in enumerate([200, 160, 260, 220, 300, 120, 300, 170])
            ],
        ]

        self._service.spreadsheets().batchUpdate(
            spreadsheetId=self.sheet_id,
            body={"requests": base_requests + format_requests},
        ).execute()

        self._pending_results = []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_or_create_tab(self, title: str) -> int:
        meta = self._service.spreadsheets().get(spreadsheetId=self.sheet_id).execute()
        for s in meta["sheets"]:
            if s["properties"]["title"] == title:
                return s["properties"]["sheetId"]
        resp = self._service.spreadsheets().batchUpdate(
            spreadsheetId=self.sheet_id,
            body={"requests": [{"addSheet": {"properties": {"title": title}}}]},
        ).execute()
        return resp["replies"][0]["addSheet"]["properties"]["sheetId"]


def _row_color(tab_id: int, row_idx: int, color: dict) -> dict:
    return {
        "repeatCell": {
            "range": {"sheetId": tab_id, "startRowIndex": row_idx, "endRowIndex": row_idx + 1},
            "cell": {"userEnteredFormat": {"backgroundColor": color}},
            "fields": "userEnteredFormat.backgroundColor",
        }
    }


def _fmt_ts(iso: str) -> str:
    """Convert an ISO 8601 timestamp to a readable string: '2026-04-17 at 02:45:12 UTC'"""
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.strftime("%Y-%m-%d at %H:%M:%S UTC")
    except (ValueError, TypeError):
        return iso  # fall back to raw value if unparseable


def _plain_english(f: Finding) -> str:
    """Return a one-sentence plain-English explanation suitable for a non-technical reader."""
    explanations = {
        "CWE-319": "Your site can be reached over plain HTTP, which means data sent between the browser and server isn't forced to be encrypted.",
        "CWE-1021": "Your site could be embedded inside another website in an invisible frame, tricking users into clicking things they didn't intend to.",
        "CWE-693": "Your site doesn't restrict what content browsers can load, increasing the risk of attackers injecting malicious scripts.",
        "CWE-200": "Your site leaks information about where users came from to third-party sites they navigate to.",
        "CWE-732": "Your site doesn't tell browsers which hardware features (camera, microphone, location) are off-limits.",
        "CWE-295": "Your HTTPS certificate has a problem — browsers may warn users or block the connection entirely.",
        "CWE-326": "Your site supports an outdated encryption standard that has known weaknesses.",
        "CWE-312": "Sensitive credentials (API keys, passwords, or private keys) are visible in your site's public responses.",
        "CWE-209": "Your site is showing internal error details to users, which reveals how your code works and makes attacks easier.",
        "CWE-548": "Your web server is listing all files in a folder publicly, exposing files that should be private.",
        "CWE-306": f"The path '{f.component}' is publicly accessible without any login, which may expose admin tools or sensitive files.",
        "CWE-614": "This cookie can travel over unencrypted HTTP, meaning anyone on the same network can intercept and steal it.",
        "CWE-1004": "JavaScript on the page can read this cookie — if your site has an XSS vulnerability, attackers can steal login sessions.",
        "CWE-352": "Without SameSite protection, other websites can trick your users' browsers into making requests that carry their cookies.",
        "CWE-942": "Your site allows any other website to read its responses, which could expose data to malicious sites.",
        "CWE-183": "Your domain's email security settings are missing or weak, allowing anyone to send emails pretending to be you.",
        "CWE-1104": "Your site loads an old version of a JavaScript library that has known security holes attackers can exploit.",
        "CWE-749": "Your server has dangerous commands enabled that attackers can use to extract information or modify data.",
        "CWE-205": "There is no file telling security researchers how to report vulnerabilities they find on your site.",
    }
    return explanations.get(f.cwe_id, f.description)
