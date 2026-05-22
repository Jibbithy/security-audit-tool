#!/usr/bin/env python3
"""
One-time script: writes a human-readable Instructions tab to the Google Sheet.
Run once after setup to document how to use the sheet.
"""
from pathlib import Path
from google.oauth2 import service_account
from googleapiclient.discovery import build
from dotenv import load_dotenv
import os

load_dotenv()

CREDS_PATH = os.environ["GOOGLE_SHEETS_CREDS_JSON"]
SHEET_ID = os.environ["AUDIT_SHEET_ID"]
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]

INSTRUCTIONS = [
    # Row 1: Title
    ["Security Audit Tool — How to Use This Sheet"],
    [""],

    # Section: Adding targets
    ["STEP 1 — Add Target Websites"],
    ["Go to the 'Targets' tab and add one URL per row starting at row 2."],
    [""],
    ["Column", "What to put here", "Example", "Notes"],
    ["A — Target URL",   "Full URL of the site to audit",          "https://example.com",    "Must include https:// or http://"],
    ["B — Scope",        "Which checks to run (see scopes below)", "FULL_PASSIVE",           "Leave blank = FULL_PASSIVE"],
    ["C — Status",       "Set to PENDING to queue it",             "PENDING",                "Tool updates this automatically after each run"],
    ["D — Last Audit",   "Filled in automatically",                "",                       "Do not edit — tool writes here"],
    ["E — Finding Count","Filled in automatically",                "",                       "Do not edit — tool writes here"],
    ["F — Max CVSS",     "Filled in automatically",                "",                       "Score 0–10; higher = more severe"],
    ["G — Trend",        "Filled in automatically",                "",                       "↑ new findings  ↓ fixed  → stable"],
    [""],

    # Section: Scopes
    ["STEP 2 — Choose a Scope"],
    ["Scope", "What it checks", "Use when"],
    ["FULL_PASSIVE",  "All checks: headers, TLS, secrets, sensitive paths, tech stack", "Default — full audit of a new site"],
    ["HEADERS_ONLY",  "HTTP security headers only (HSTS, CSP, X-Frame, etc.)",          "Quick check on header configuration"],
    ["TLS_ONLY",      "TLS certificate validity, expiry, and protocol version",          "Checking cert health only"],
    ["SECRETS",       "API keys, private keys, stack traces exposed in responses",       "Checking for info disclosure"],
    ["AUTH",          "Unauthenticated access to admin/API/config paths",                "Checking access control"],
    [""],

    # Section: Running the tool
    ["STEP 3 — Run the Audit"],
    ["Open a terminal and run:"],
    [""],
    ["    cd ~/security-audit-tool"],
    ["    source .venv/bin/activate"],
    ["    python main.py run"],
    [""],
    ["Useful flags:"],
    ["Flag", "What it does"],
    ["--dry-run",          "Reads the sheet and prints targets — makes no API calls. Use to verify setup."],
    ["--no-pdf",           "Skips PDF generation (faster). HTML report is always generated."],
    ["--max-concurrent 3", "Override max parallel agents (default: 5). Lower = slower but gentler on rate limits."],
    [""],
    ["To check audit history for a specific site:"],
    ["    python main.py history https://example.com"],
    [""],

    # Section: Reading results
    ["STEP 4 — Read the Results"],
    ["After a run completes:"],
    ["  • This sheet's Targets tab updates with finding count, max CVSS score, and trend."],
    ["  • HTML reports are saved to: ~/security-audit-tool/reports/"],
    ["  • Each report includes: executive summary, findings table (sorted by CVSS), remediation roadmap."],
    ["  • CVSS score guide:  9.0–10.0 = Critical  |  7.0–8.9 = High  |  4.0–6.9 = Medium  |  0.1–3.9 = Low"],
    [""],

    # Section: Security
    ["SECURITY — Protecting Your Credentials"],
    ["DO NOT paste API keys or credentials into this sheet or any cell — Google Sheets are not secure storage."],
    [""],
    ["Where credentials are stored (on your machine only):"],
    ["File", "What it contains", "Permissions"],
    ["~/.security-audit-tool/.env",            "ANTHROPIC_API_KEY and Google Sheet ID", "600 — only you can read it"],
    ["~/security-audit-tool/service-account.json", "Google service account private key",    "600 — only you can read it"],
    ["~/security-audit-tool/oauth-client.json",    "OAuth app credentials (one-time setup)", "600 — only you can read it"],
    ["~/security-audit-tool/oauth-token.json",     "OAuth refresh token (one-time setup)",   "600 — only you can read it"],
    [""],
    ["These files are listed in .gitignore and will NEVER be committed to git."],
    ["If you believe a key was exposed, rotate it immediately:"],
    ["  • Anthropic key: https://console.anthropic.com/settings/keys"],
    ["  • Google service account: GCP Console → IAM → Service Accounts → Keys → Delete & recreate"],
]

TAB_TITLE = "Instructions"

# Widths for columns A–D (in pixels)
COL_WIDTHS = [260, 340, 220, 300]


def get_or_create_tab(service, sheet_id: str) -> int:
    """Return the sheetId (tab ID) for Instructions, creating it if absent."""
    meta = service.spreadsheets().get(spreadsheetId=sheet_id).execute()
    for s in meta["sheets"]:
        if s["properties"]["title"] == TAB_TITLE:
            return s["properties"]["sheetId"]

    # Create the tab
    resp = service.spreadsheets().batchUpdate(
        spreadsheetId=sheet_id,
        body={"requests": [{"addSheet": {"properties": {"title": TAB_TITLE}}}]},
    ).execute()
    return resp["replies"][0]["addSheet"]["properties"]["sheetId"]


def write_instructions(service, sheet_id: str):
    service.spreadsheets().values().update(
        spreadsheetId=sheet_id,
        range=f"{TAB_TITLE}!A1",
        valueInputOption="RAW",
        body={"values": INSTRUCTIONS},
    ).execute()


def format_tab(service, sheet_id: str, tab_id: int):
    requests = []

    # Title row (row 1): large bold white on dark background
    requests.append({
        "repeatCell": {
            "range": {"sheetId": tab_id, "startRowIndex": 0, "endRowIndex": 1},
            "cell": {
                "userEnteredFormat": {
                    "backgroundColor": {"red": 0.102, "green": 0.102, "blue": 0.18},
                    "textFormat": {
                        "foregroundColor": {"red": 1, "green": 1, "blue": 1},
                        "bold": True,
                        "fontSize": 14,
                    },
                    "padding": {"top": 8, "bottom": 8, "left": 8},
                }
            },
            "fields": "userEnteredFormat(backgroundColor,textFormat,padding)",
        }
    })

    # Section header rows: rows that start with "STEP" or "SECURITY"
    section_indices = [
        i for i, row in enumerate(INSTRUCTIONS)
        if row and (row[0].startswith("STEP") or row[0].startswith("SECURITY"))
    ]
    for idx in section_indices:
        requests.append({
            "repeatCell": {
                "range": {"sheetId": tab_id, "startRowIndex": idx, "endRowIndex": idx + 1},
                "cell": {
                    "userEnteredFormat": {
                        "backgroundColor": {"red": 0.18, "green": 0.22, "blue": 0.36},
                        "textFormat": {
                            "foregroundColor": {"red": 1, "green": 1, "blue": 1},
                            "bold": True,
                            "fontSize": 11,
                        },
                    }
                },
                "fields": "userEnteredFormat(backgroundColor,textFormat)",
            }
        })

    # Column header rows (contain "Column", "Scope", "Flag", "File")
    col_header_indices = [
        i for i, row in enumerate(INSTRUCTIONS)
        if row and row[0] in ("Column", "Scope", "Flag", "File")
    ]
    for idx in col_header_indices:
        requests.append({
            "repeatCell": {
                "range": {"sheetId": tab_id, "startRowIndex": idx, "endRowIndex": idx + 1},
                "cell": {
                    "userEnteredFormat": {
                        "backgroundColor": {"red": 0.85, "green": 0.87, "blue": 0.95},
                        "textFormat": {"bold": True},
                    }
                },
                "fields": "userEnteredFormat(backgroundColor,textFormat)",
            }
        })

    # Set column widths
    for col_idx, width in enumerate(COL_WIDTHS):
        requests.append({
            "updateDimensionProperties": {
                "range": {
                    "sheetId": tab_id,
                    "dimension": "COLUMNS",
                    "startIndex": col_idx,
                    "endIndex": col_idx + 1,
                },
                "properties": {"pixelSize": width},
                "fields": "pixelSize",
            }
        })

    # Freeze row 1
    requests.append({
        "updateSheetProperties": {
            "properties": {
                "sheetId": tab_id,
                "gridProperties": {"frozenRowCount": 1},
            },
            "fields": "gridProperties.frozenRowCount",
        }
    })

    # Wrap text in all cells
    requests.append({
        "repeatCell": {
            "range": {"sheetId": tab_id},
            "cell": {
                "userEnteredFormat": {
                    "wrapStrategy": "WRAP",
                }
            },
            "fields": "userEnteredFormat.wrapStrategy",
        }
    })

    service.spreadsheets().batchUpdate(
        spreadsheetId=sheet_id, body={"requests": requests}
    ).execute()


def main():
    creds = service_account.Credentials.from_service_account_file(CREDS_PATH, scopes=SCOPES)
    service = build("sheets", "v4", credentials=creds)

    print(f"Writing Instructions tab to sheet {SHEET_ID}...")
    tab_id = get_or_create_tab(service, SHEET_ID)
    write_instructions(service, SHEET_ID)
    format_tab(service, SHEET_ID, tab_id)
    print("Done. Open the sheet and check the Instructions tab.")
    print(f"Sheet: https://docs.google.com/spreadsheets/d/{SHEET_ID}/edit")


if __name__ == "__main__":
    main()
