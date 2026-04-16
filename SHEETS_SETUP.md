# Google Sheets Setup Guide

## 1. Create a Google Cloud Project
1. Go to https://console.cloud.google.com
2. Create a new project (e.g., "security-audit-tool")
3. Enable the Google Sheets API: APIs & Services → Library → "Google Sheets API" → Enable

## 2. Create a Service Account
1. APIs & Services → Credentials → Create Credentials → Service Account
2. Name: "security-audit-sa"
3. Click the service account → Keys → Add Key → JSON
4. Save the downloaded JSON as: `/home/jimmy/security-audit-tool/service-account.json`

## 3. Create the Google Sheet
1. Go to https://sheets.google.com and create a new spreadsheet
2. Rename the first tab to **Targets**
3. Share it with the service account email (found in the JSON, field `"client_email"`) — give Editor role
4. Copy the Sheet ID from the URL: `https://docs.google.com/spreadsheets/d/SHEET_ID/edit`

## 4. Set Up Column Headers in Row 1 of the "Targets" Tab

Add these headers exactly in row 1:

| A | B | C | D | E | F | G |
|---|---|---|---|---|---|---|
| Target URL | Scope | Status | Last Audit | Finding Count | Max CVSS | Trend |

Then add your target URLs starting in row 2, e.g.:

| https://example.com | FULL_PASSIVE | PENDING | | | | |

**Scope values:** `FULL_PASSIVE`, `HEADERS_ONLY`, `TLS_ONLY`, `SECRETS`, `AUTH`

## 5. Configure .env

Copy `.env.example` to `.env` and fill in:

```
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_SHEETS_CREDS_JSON=/home/jimmy/security-audit-tool/service-account.json
AUDIT_SHEET_ID=<paste-your-sheet-id-here>
```

## 6. Run Your First Audit

```bash
cd ~/security-audit-tool
source .venv/bin/activate

# Dry run first to confirm targets are read correctly
python main.py run --dry-run

# Full audit (generates HTML/PDF reports in ./reports/)
python main.py run

# View history for a specific target
python main.py history https://example.com
```
