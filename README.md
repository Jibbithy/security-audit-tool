# Security Audit Tool

Runs passive security checks against a list of websites in parallel. Claude reviews the findings to filter out false positives, and the tool writes an HTML/PDF report for each site, tracking results over time in Google Sheets.

"Passive" means it only reads what a site already serves to any visitor: headers, certificates, DNS records, public files and page source. It doesn't log in, fuzz, brute-force or send attack payloads.

**Only audit sites you own or have written permission to test.**

## What it checks

| Probe | Looks for |
|---|---|
| Headers | Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) |
| TLS | Invalid, self-signed, expired or soon-to-expire certificates, and outdated TLS versions |
| Secrets | API keys and tokens exposed in the response |
| Auth | Admin pages, API docs and files like `.env` that load without logging in |
| Cookies | Missing `Secure`, `HttpOnly` and `SameSite` flags |
| CORS | Wildcard origins and origin reflection |
| Email security | Missing or weak SPF and DMARC records |
| HTTP methods | TRACE and other risky methods left enabled |
| JS libraries | Outdated front-end JavaScript libraries |
| Mixed content | HTTP resources loaded on HTTPS pages |
| Inventory | Server software and versions revealed in headers |
| robots.txt, sitemap.xml, security.txt | Sensitive paths listed publicly, or no security contact published |

Each finding gets a severity, a CVSS score, a CWE ID, an OWASP category and a suggested fix.

## How it works

1. Reads target URLs and their scope from a **Targets** tab in Google Sheets.
2. Audits up to `MAX_CONCURRENT_AGENTS` sites at a time with `asyncio`.
3. Sends each site's findings to Claude, which flags likely false positives and drops them.
4. Saves the results to a local SQLite database and compares them with the last run (new, fixed or stable).
5. Writes an HTML report, plus a PDF if you want one, and updates the sheet with the finding count, highest CVSS score and trend.

If the Claude call fails, the tool keeps every finding rather than losing them.

## Setup

Requires Python 3.11+. WeasyPrint (used for PDFs) also needs its [system libraries](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # then fill in your own values
```

`.env` needs an Anthropic API key, the path to a Google service account JSON file and your sheet's ID. [SHEETS_SETUP.md](SHEETS_SETUP.md) walks through creating the service account and the sheet.

## Usage

```bash
# Check one site and print every finding. Nothing is saved.
python main.py check example.com

# Show which targets would run, without auditing anything
python main.py run --dry-run

# Audit every PENDING target in the sheet and write reports to ./reports/
python main.py run

# Show past findings for one site
python main.py history https://example.com
```

Scopes: `FULL_PASSIVE` (all probes), `HEADERS_ONLY`, `TLS_ONLY`, `SECRETS`, `AUTH` and `EMAIL`.

## Tests

```bash
pytest
```
