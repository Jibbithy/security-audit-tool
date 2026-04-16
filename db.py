import sqlite3
from probes.base import Finding, Severity, RunDelta

_CREATE_RUNS = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL
);
"""

_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    target_url TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL NOT NULL,
    cvss_vector TEXT NOT NULL,
    cwe_id TEXT NOT NULL,
    owasp_category TEXT NOT NULL,
    component TEXT NOT NULL,
    remediation TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);
"""


class Database:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(_CREATE_RUNS)
        self.conn.execute(_CREATE_FINDINGS)
        self.conn.commit()

    def save_run(self, run_id: str, target_url: str, started_at: str, completed_at: str):
        self.conn.execute(
            "INSERT OR REPLACE INTO runs VALUES (?,?,?,?)",
            (run_id, target_url, started_at, completed_at),
        )
        self.conn.commit()

    def save_finding(self, f: Finding):
        self.conn.execute(
            "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f.id, f.run_id, f.target_url, f.title, f.description,
             f.severity.value, f.cvss_score, f.cvss_vector, f.cwe_id,
             f.owasp_category, f.component, f.remediation, f.detected_at),
        )
        self.conn.commit()

    def get_findings_for_target(self, target_url: str) -> list[Finding]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE target_url = ? ORDER BY detected_at",
            (target_url,),
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_findings_for_run(self, run_id: str) -> list[Finding]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE run_id = ?", (run_id,)
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_prior_run_id(self, target_url: str, current_run_id: str) -> str | None:
        row = self.conn.execute(
            """SELECT run_id FROM runs
               WHERE target_url = ? AND run_id != ?
               ORDER BY started_at DESC LIMIT 1""",
            (target_url, current_run_id),
        ).fetchone()
        return row["run_id"] if row else None

    def compute_delta(self, target_url: str, current_run_id: str) -> RunDelta:
        prior_run_id = self.get_prior_run_id(target_url, current_run_id)
        current = self.get_findings_for_run(current_run_id)
        if not prior_run_id:
            return RunDelta(new_findings=current, fixed_finding_ids=[], regressed_findings=[])
        prior = self.get_findings_for_run(prior_run_id)
        prior_by_cwe = {f.cwe_id: f for f in prior}
        current_by_cwe = {f.cwe_id: f for f in current}
        new = [f for f in current if f.cwe_id not in prior_by_cwe]
        fixed = [f.id for f in prior if f.cwe_id not in current_by_cwe]
        regressed = [
            f for f in current
            if f.cwe_id in prior_by_cwe and f.cvss_score > prior_by_cwe[f.cwe_id].cvss_score
        ]
        return RunDelta(new_findings=new, fixed_finding_ids=fixed, regressed_findings=regressed)

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        return Finding(
            id=row["id"], run_id=row["run_id"], target_url=row["target_url"],
            title=row["title"], description=row["description"],
            severity=Severity(row["severity"]), cvss_score=row["cvss_score"],
            cvss_vector=row["cvss_vector"], cwe_id=row["cwe_id"],
            owasp_category=row["owasp_category"], component=row["component"],
            remediation=row["remediation"], detected_at=row["detected_at"],
        )
