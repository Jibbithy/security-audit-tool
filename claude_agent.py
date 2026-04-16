import asyncio, json
import anthropic
from probes.base import Finding

_SYSTEM_PROMPT = """You are a senior application security engineer conducting a passive security audit review.
You are given a target URL and a list of findings from automated passive probes.
Your job:
1. Review findings for accuracy. Identify any that are likely false positives.
2. Provide an overall risk level assessment.
3. Note any additional security concerns evident from the finding patterns.

Respond ONLY with a JSON object — no markdown, no explanation outside JSON:
{
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "summary": "2-3 sentence executive summary",
  "false_positive_ids": ["finding-id-1", ...],
  "additional_notes": "any patterns or concerns not captured in findings"
}"""


async def audit_target_with_claude(
    target_url: str,
    run_id: str,
    findings: list[Finding],
    api_key: str,
    timeout: int = 120,
) -> list[Finding]:
    """Send probe findings to Claude for AI analysis. Returns findings with false positives removed."""
    if not findings:
        return []

    client = anthropic.Anthropic(api_key=api_key)
    findings_text = "\n".join(
        f"- ID:{f.id} [{f.cwe_id}] {f.title} (CVSS {f.cvss_score}, {f.severity.value}): {f.description}"
        for f in findings
    )
    user_message = f"Target URL: {target_url}\n\nFindings:\n{findings_text}"

    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(
                client.messages.create,
                model="claude-sonnet-4-6",
                max_tokens=1024,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            ),
            timeout=timeout,
        )
        analysis = json.loads(response.content[0].text)
        fp_ids = set(analysis.get("false_positive_ids", []))
        return [f for f in findings if f.id not in fp_ids]
    except Exception:
        # On any failure, return original findings unmodified
        return findings
