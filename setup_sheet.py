#!/usr/bin/env python3
"""
One-time setup script: creates and configures the Google Sheet for the security audit tool.

Before running:
  1. Go to https://console.cloud.google.com
  2. Create a project (or select existing)
  3. Enable Google Sheets API:
       APIs & Services → Library → "Google Sheets API" → Enable
  4. Create OAuth credentials:
       APIs & Services → Credentials → Create Credentials → OAuth 2.0 Client IDs
       Application type: Desktop app  →  Create  →  Download JSON
  5. Save the downloaded file as: ~/security-audit-tool/oauth-client.json
  6. Run: python setup_sheet.py

The script will open your browser for a one-time Google login, then:
  - Create a new Google Sheet called "Security Audit Targets"
  - Set up the Targets tab with correct headers
  - Add an example row
  - Create the service account JSON stub (if path provided)
  - Print the Sheet ID to add to your .env
"""

import json
import os
import sys
from pathlib import Path

OAUTH_CLIENT_FILE = Path(__file__).parent / "oauth-client.json"
TOKEN_FILE = Path(__file__).parent / "oauth-token.json"
ENV_FILE = Path(__file__).parent / ".env"

SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive.file",
]

HEADERS = [
    ["Target URL", "Scope", "Status", "Last Audit", "Finding Count", "Max CVSS", "Trend"]
]

EXAMPLE_ROWS = [
    ["https://example.com", "FULL_PASSIVE", "PENDING", "", "", "", ""],
]

HEADER_FORMATS = {
    "backgroundColor": {"red": 0.102, "green": 0.102, "blue": 0.18},
    "foregroundColor": {"red": 1.0, "green": 1.0, "blue": 1.0},
    "bold": True,
}

SCOPE_NOTE = (
    "Scope values: FULL_PASSIVE, HEADERS_ONLY, TLS_ONLY, SECRETS, AUTH\n"
    "Add your target URLs in column A starting from row 2."
)


def get_credentials():
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request

    creds = None
    if TOKEN_FILE.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not OAUTH_CLIENT_FILE.exists():
                print(f"\nERROR: OAuth client file not found at: {OAUTH_CLIENT_FILE}")
                print("\nTo get it:")
                print("  1. Go to https://console.cloud.google.com")
                print("  2. Select or create a project")
                print("  3. APIs & Services → Library → 'Google Sheets API' → Enable")
                print("  4. APIs & Services → Credentials → Create Credentials")
                print("     → OAuth 2.0 Client IDs → Desktop app → Create → Download JSON")
                print(f"  5. Save as: {OAUTH_CLIENT_FILE}")
                sys.exit(1)
            flow = InstalledAppFlow.from_client_secrets_file(str(OAUTH_CLIENT_FILE), SCOPES)
            # run_local_server with open_browser=False prints the URL for manual opening
            # Works in headless/VSCode environments where no browser can auto-launch
            creds = flow.run_local_server(port=8088, open_browser=False)

        TOKEN_FILE.write_text(creds.to_json())
        print(f"Credentials saved to {TOKEN_FILE}")

    return creds


def create_spreadsheet(service):
    body = {
        "properties": {"title": "Security Audit Targets"},
        "sheets": [{"properties": {"title": "Targets"}}],
    }
    sheet = service.spreadsheets().create(body=body, fields="spreadsheetId,spreadsheetUrl").execute()
    return sheet["spreadsheetId"], sheet["spreadsheetUrl"]


def write_headers_and_examples(service, sheet_id):
    # Write headers + example rows
    values = HEADERS + EXAMPLE_ROWS
    service.spreadsheets().values().update(
        spreadsheetId=sheet_id,
        range="Targets!A1",
        valueInputOption="RAW",
        body={"values": values},
    ).execute()

    # Write scope note in a note cell below
    service.spreadsheets().values().update(
        spreadsheetId=sheet_id,
        range="Targets!A10",
        valueInputOption="RAW",
        body={"values": [[SCOPE_NOTE]]},
    ).execute()


def format_headers(service, sheet_id):
    # Get sheet ID (tab ID) for the Targets sheet
    meta = service.spreadsheets().get(spreadsheetId=sheet_id).execute()
    tab_id = meta["sheets"][0]["properties"]["sheetId"]

    requests = [
        # Bold + dark background on header row
        {
            "repeatCell": {
                "range": {"sheetId": tab_id, "startRowIndex": 0, "endRowIndex": 1},
                "cell": {
                    "userEnteredFormat": {
                        "backgroundColor": HEADER_FORMATS["backgroundColor"],
                        "textFormat": {
                            "foregroundColor": HEADER_FORMATS["foregroundColor"],
                            "bold": HEADER_FORMATS["bold"],
                        },
                    }
                },
                "fields": "userEnteredFormat(backgroundColor,textFormat)",
            }
        },
        # Freeze header row
        {
            "updateSheetProperties": {
                "properties": {
                    "sheetId": tab_id,
                    "gridProperties": {"frozenRowCount": 1},
                },
                "fields": "gridProperties.frozenRowCount",
            }
        },
        # Auto-resize all columns
        {
            "autoResizeDimensions": {
                "dimensions": {
                    "sheetId": tab_id,
                    "dimension": "COLUMNS",
                    "startIndex": 0,
                    "endIndex": 7,
                }
            }
        },
    ]
    service.spreadsheets().batchUpdate(
        spreadsheetId=sheet_id, body={"requests": requests}
    ).execute()


def update_env_file(sheet_id):
    if not ENV_FILE.exists():
        print(f"\n.env not found. Creating from .env.example...")
        example = Path(__file__).parent / ".env.example"
        if example.exists():
            ENV_FILE.write_text(example.read_text())

    content = ENV_FILE.read_text() if ENV_FILE.exists() else ""
    if "AUDIT_SHEET_ID=" in content:
        lines = content.splitlines()
        lines = [
            f"AUDIT_SHEET_ID={sheet_id}" if l.startswith("AUDIT_SHEET_ID=") else l
            for l in lines
        ]
        ENV_FILE.write_text("\n".join(lines) + "\n")
        print(f"Updated AUDIT_SHEET_ID in {ENV_FILE}")
    else:
        with open(ENV_FILE, "a") as f:
            f.write(f"\nAUDIT_SHEET_ID={sheet_id}\n")
        print(f"Added AUDIT_SHEET_ID to {ENV_FILE}")


def main():
    print("Security Audit Tool — Google Sheet Setup")
    print("=" * 45)

    print("\nStep 1: Authenticating with Google...")
    creds = get_credentials()

    from googleapiclient.discovery import build
    service = build("sheets", "v4", credentials=creds)

    print("Step 2: Creating spreadsheet 'Security Audit Targets'...")
    sheet_id, sheet_url = create_spreadsheet(service)
    print(f"  Created: {sheet_url}")

    print("Step 3: Writing headers and example rows...")
    write_headers_and_examples(service, sheet_id)

    print("Step 4: Formatting headers...")
    format_headers(service, sheet_id)

    print("Step 5: Updating .env with Sheet ID...")
    update_env_file(sheet_id)

    print("\n" + "=" * 45)
    print("SETUP COMPLETE")
    print("=" * 45)
    print(f"\nSheet URL:  {sheet_url}")
    print(f"Sheet ID:   {sheet_id}")
    print(f"\nNext steps:")
    print(f"  1. Open the sheet and verify it looks correct")
    print(f"  2. Add your target URLs in column A starting from row 2")
    print(f"  3. Set up a service account for the main tool (see SHEETS_SETUP.md)")
    print(f"     The main tool needs a service account to run without browser login.")
    print(f"  4. Share the sheet with your service account email (Editor role)")
    print(f"  5. Add ANTHROPIC_API_KEY and GOOGLE_SHEETS_CREDS_JSON to .env")
    print(f"  6. Run: python main.py run --dry-run")


if __name__ == "__main__":
    main()
