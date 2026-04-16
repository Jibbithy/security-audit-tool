import os
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from probes.base import Finding, Severity, RunDelta


def generate_report(
    target_url: str,
    run_id: str,
    scope: str,
    findings: list[Finding],
    delta: RunDelta | None,
    output_dir: str,
    generate_pdf: bool = True,
) -> str:
    """Render report. Returns path to the generated HTML file."""
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html.j2")

    counts = {sev.value: 0 for sev in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    max_cvss = max((f.cvss_score for f in findings), default=0.0)

    if counts["critical"] > 0:
        summary = (
            f"CRITICAL risk. {counts['critical']} critical and {counts['high']} high severity findings "
            "require immediate remediation."
        )
    elif counts["high"] > 0:
        summary = f"HIGH risk. {counts['high']} high severity findings detected. Remediation recommended within 7 days."
    elif counts["medium"] > 0:
        summary = f"MEDIUM risk. {counts['medium']} medium severity findings detected. Remediate within 30 days."
    else:
        summary = "LOW risk. No critical or high severity findings. Address remaining items in routine maintenance."

    html = template.render(
        target_url=target_url,
        run_id=run_id,
        scope=scope,
        findings=findings,
        delta=delta,
        counts=counts,
        max_cvss=round(max_cvss, 1),
        audit_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        summary=summary,
    )

    safe_name = target_url.replace("https://", "").replace("http://", "").replace("/", "_").rstrip("_")
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = f"{safe_name}_{date_str}_{run_id[:8]}.html"
    html_path = os.path.join(output_dir, filename)
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    with open(html_path, "w") as fh:
        fh.write(html)

    if generate_pdf:
        try:
            from weasyprint import HTML as WPhtml
            WPhtml(filename=html_path).write_pdf(html_path.replace(".html", ".pdf"))
        except Exception:
            pass  # PDF is best-effort; HTML is the primary output

    return html_path
