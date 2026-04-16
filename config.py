import os
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

_REQUIRED = ["ANTHROPIC_API_KEY", "GOOGLE_SHEETS_CREDS_JSON", "AUDIT_SHEET_ID"]


@dataclass
class Config:
    anthropic_api_key: str
    google_sheets_creds_json: str
    audit_sheet_id: str
    max_concurrent_agents: int
    agent_timeout_seconds: int
    report_output_dir: str
    db_path: str

    def __init__(self):
        missing = [k for k in _REQUIRED if not os.getenv(k)]
        if missing:
            raise EnvironmentError(
                f"Missing required environment variables: {', '.join(missing)}\n"
                "Copy .env.example to .env and fill in the values."
            )
        self.anthropic_api_key = os.environ["ANTHROPIC_API_KEY"]
        self.google_sheets_creds_json = os.environ["GOOGLE_SHEETS_CREDS_JSON"]
        self.audit_sheet_id = os.environ["AUDIT_SHEET_ID"]
        self.max_concurrent_agents = int(os.getenv("MAX_CONCURRENT_AGENTS", "5"))
        self.agent_timeout_seconds = int(os.getenv("AGENT_TIMEOUT_SECONDS", "120"))
        self.report_output_dir = os.getenv("REPORT_OUTPUT_DIR", "./reports")
        self.db_path = os.getenv("DB_PATH", "./audit.db")
        Path(self.report_output_dir).mkdir(parents=True, exist_ok=True)
