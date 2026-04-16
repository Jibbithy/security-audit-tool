import asyncio, uuid
from datetime import datetime, timezone
from probes.base import AuditTarget, Finding
from probes.owasp import run_full_passive_audit
from claude_agent import audit_target_with_claude
from db import Database


async def _audit_one(
    target: AuditTarget,
    api_key: str,
    timeout: int,
    db: Database,
    semaphore: asyncio.Semaphore,
) -> tuple[str, list[Finding]]:
    """Audit a single target. Returns (run_id, findings)."""
    async with semaphore:
        run_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()

        # Run passive probes in a thread (blocking I/O)
        raw_findings = await asyncio.to_thread(
            run_full_passive_audit, target.url, run_id, target.scope
        )

        # Claude AI analysis + false-positive filtering
        findings = await audit_target_with_claude(
            target_url=target.url,
            run_id=run_id,
            findings=raw_findings,
            api_key=api_key,
            timeout=timeout,
        )

        completed_at = datetime.now(timezone.utc).isoformat()
        db.save_run(run_id, target.url, started_at, completed_at)
        for f in findings:
            db.save_finding(f)

        return run_id, findings


async def run_audit_batch(
    targets: list[AuditTarget],
    api_key: str,
    db: Database,
    max_concurrent: int = 5,
    timeout: int = 120,
) -> dict[str, tuple[str, list[Finding]]]:
    """
    Audit all targets with max_concurrent concurrency.
    Returns dict: target_url -> (run_id, findings)
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    results: dict[str, tuple[str, list[Finding]]] = {}

    async def run_and_store(target: AuditTarget):
        run_id, findings = await _audit_one(target, api_key, timeout, db, semaphore)
        results[target.url] = (run_id, findings)

    await asyncio.gather(*[run_and_store(t) for t in targets])
    return results
