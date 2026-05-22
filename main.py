#!/usr/bin/env python3
import asyncio
from datetime import datetime, timezone
import click
from config import Config
from db import Database
from sheets import SheetsSync
from orchestrator import run_audit_batch
from reporter import generate_report


@click.group()
def cli():
    """Security Audit Orchestration Tool — passive web security audits powered by Claude AI."""


@cli.command()
@click.option("--max-concurrent", default=None, type=int, help="Override MAX_CONCURRENT_AGENTS env var")
@click.option("--pdf/--no-pdf", default=True, help="Generate PDF alongside HTML report")
@click.option("--dry-run", is_flag=True, help="Read targets but skip audits and Sheet writes")
def run(max_concurrent, pdf, dry_run):
    """Run security audits for all PENDING targets in Google Sheets."""
    config = Config()
    db = Database(config.db_path)
    sheets = SheetsSync(config.google_sheets_creds_json, config.audit_sheet_id)

    click.echo("Reading targets from Google Sheets...")
    targets = sheets.read_targets()

    if not targets:
        click.echo("No targets found. Add URLs to column A of the 'Targets' sheet.")
        return

    click.echo(f"Found {len(targets)} target(s). Starting audit...")
    if dry_run:
        for t in targets:
            click.echo(f"  [DRY RUN] {t.url}  scope={t.scope}  priority={t.priority}")
        return

    concurrent = max_concurrent or config.max_concurrent_agents
    results = asyncio.run(run_audit_batch(
        targets=targets,
        api_key=config.anthropic_api_key,
        db=db,
        max_concurrent=concurrent,
        timeout=config.agent_timeout_seconds,
    ))

    for target in targets:
        run_id, findings = results.get(target.url, ("unknown", []))
        delta = db.compute_delta(target.url, run_id) if run_id != "unknown" else None

        trend = ""
        if delta:
            if delta.new_findings:
                trend = f"up +{len(delta.new_findings)} new"
            elif delta.fixed_finding_ids:
                trend = f"down {len(delta.fixed_finding_ids)} fixed"
            else:
                trend = "stable"

        report_path = generate_report(
            target_url=target.url,
            run_id=run_id,
            scope=target.scope,
            findings=findings,
            delta=delta,
            output_dir=config.report_output_dir,
            generate_pdf=pdf,
        )
        sheets.write_results(target, findings, trend)
        sheets.write_results_detail(
            run_id=run_id,
            url=target.url,
            findings=findings,
            started_at=datetime.now(timezone.utc).strftime("%Y-%m-%d at %H:%M:%S UTC"),
        )

        severity_counts: dict[str, int] = {}
        for f in findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        click.echo(f"  [OK] {target.url}  findings={len(findings)} {severity_counts}  trend={trend}")
        click.echo(f"       Report: {report_path}")

    sheets.write_all_results_detail()
    click.echo(f"\nAudit complete. Reports saved to: {config.report_output_dir}/")


@cli.command()
@click.argument("url")
@click.option("--scope", default="FULL_PASSIVE", help="Probe scope (default: FULL_PASSIVE)")
def check(url, scope):
    """Run all probes against a URL and print every finding in detail. No DB or Sheet writes."""
    from probes.owasp import run_full_passive_audit, _SCOPE_PROBES, _ALL_PROBES
    from probes.base import Severity

    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    probe_classes = _SCOPE_PROBES.get(scope, _ALL_PROBES)
    probe_names = [p.__name__.replace("Probe", "") for p in probe_classes]

    click.echo(f"\nTarget : {url}")
    click.echo(f"Scope  : {scope}  ({len(probe_classes)} probes: {', '.join(probe_names)})")
    click.echo("─" * 70)

    severity_colors = {
        Severity.CRITICAL: "red",
        Severity.HIGH:     "bright_red",
        Severity.MEDIUM:   "yellow",
        Severity.LOW:      "green",
        Severity.INFO:     "white",
    }

    import uuid
    run_id = str(uuid.uuid4())
    total = 0

    for probe_cls in probe_classes:
        name = probe_cls.__name__.replace("Probe", "")
        click.echo(f"\n[{name}]", nl=False)
        try:
            findings = probe_cls().run(url, run_id)
        except Exception as e:
            click.echo(f"  ERROR: {e}", err=True)
            continue

        if not findings:
            click.secho("  ✓ Nothing found", fg="green")
        else:
            click.echo()
            for f in sorted(findings, key=lambda x: x.cvss_score, reverse=True):
                color = severity_colors.get(f.severity, "white")
                label = f.severity.value.upper()
                click.secho(f"  [{label:8}] CVSS {f.cvss_score:4.1f}  {f.title}", fg=color, bold=True)
                click.echo(f"             {f.cwe_id} | {f.owasp_category}")
                click.echo(f"             Component : {f.component}")
                click.echo(f"             Fix       : {f.remediation}")
            total += len(findings)

    click.echo("\n" + "─" * 70)
    click.echo(f"Total findings: {total}  (no data was saved — run `python main.py run` to audit and save)")


@cli.command()
@click.argument("target_url")
def history(target_url):
    """Show audit history for a specific target URL."""
    config = Config()
    db = Database(config.db_path)
    findings = db.get_findings_for_target(target_url)
    if not findings:
        click.echo(f"No audit history found for: {target_url}")
        return
    click.echo(f"Audit history for {target_url} ({len(findings)} total findings):\n")
    for f in sorted(findings, key=lambda x: x.detected_at, reverse=True):
        click.echo(
            f"  [{f.detected_at[:10]}] [{f.severity.value.upper():8}] CVSS {f.cvss_score:4.1f} -- {f.title}"
        )


if __name__ == "__main__":
    cli()
