import logging
from pathlib import Path

import anthropic
import asyncpg

from db import search_infrastructure
from dojo import Finding, ScanContext, format_component, service_for_finding

logger = logging.getLogger(__name__)

BASE_SYSTEM_PROMPT = """\
You are a security analyst reviewing vulnerability findings exported from DefectDojo.

For each finding:
1. Assess real-world exploitability — consider attack vector, required privileges, and component exposure.
2. Determine the actual risk level, which may differ from the reported severity based on deployment context.
3. Provide a clear, actionable remediation recommendation.

If the search_infrastructure tool is available, call it before assessing risk.
Infrastructure context (public ingress, network isolation, cluster placement) is critical for accurate risk assessment.\
"""


def load_system_prompt(extra_prompt_file: str | None) -> str:
    prompt = BASE_SYSTEM_PROMPT
    if not extra_prompt_file:
        return prompt
    try:
        extra = Path(extra_prompt_file).read_text().strip()
        if extra:
            logger.info("Loaded extra prompt from %s (%d chars)", extra_prompt_file, len(extra))
            return prompt + "\n\n" + extra
    except FileNotFoundError:
        logger.warning("EXTRA_PROMPT_FILE not found: %s", extra_prompt_file)
    except Exception:
        logger.exception("Failed to load extra prompt from %s", extra_prompt_file)
    return prompt


def _format_finding(finding: Finding, ctx: ScanContext) -> str:
    parts = [
        f"Finding: {finding.title}",
        f"Severity: {finding.severity}",
    ]
    if finding.cve:
        parts.append(f"CVE: {finding.cve}")
    component = format_component(finding)
    if component:
        parts.append(f"Component: {component}")
    svc = service_for_finding(finding)
    if svc:
        parts.append(f"Service: {svc}")
    if finding.file_path:
        parts.append(f"File: {finding.file_path}")
    parts += [
        f"Scan type: {ctx.scan_type}",
        f"Product: {ctx.product_name}",
        f"Engagement: {ctx.engagement_name}",
    ]
    if finding.description:
        parts.append(f"\nDescription:\n{finding.description[:800]}")
    if finding.mitigation:
        parts.append(f"\nScanner mitigation hint:\n{finding.mitigation[:400]}")
    return "\n".join(parts)


_INFRA_TOOL = {
    "name": "search_infrastructure",
    "description": (
        "Search Kubernetes infrastructure records by service name. "
        "Returns deployment config, service type, and ingress/exposure details."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "service_name": {
                "type": "string",
                "description": "Service name to look up (e.g. 'payment-service')",
            },
        },
        "required": ["service_name"],
    },
}


async def analyze_finding(
    client: anthropic.AsyncAnthropic,
    finding: Finding,
    ctx: ScanContext,
    system_prompt: str,
    pool: asyncpg.Pool | None,
) -> str:
    tools = [_INFRA_TOOL] if pool is not None else []
    messages: list[dict] = [
        {"role": "user", "content": _format_finding(finding, ctx)},
    ]

    for _ in range(5):  # cap tool-use iterations
        kwargs: dict = dict(
            model="claude-haiku-4-5-20251001",
            max_tokens=512,
            system=system_prompt,
            messages=messages,
        )
        if tools:
            kwargs["tools"] = tools

        resp = await client.messages.create(**kwargs)

        if resp.stop_reason == "end_turn":
            return "".join(b.text for b in resp.content if hasattr(b, "text"))

        if resp.stop_reason == "tool_use":
            tool_results = []
            for block in resp.content:
                if block.type == "tool_use" and block.name == "search_infrastructure":
                    svc = block.input.get("service_name", "")
                    logger.debug("search_infrastructure(%r)", svc)
                    result = await search_infrastructure(pool, svc)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })
            if not tool_results:
                break
            messages.append({"role": "assistant", "content": resp.content})
            messages.append({"role": "user", "content": tool_results})
        else:
            break

    return "".join(b.text for b in resp.content if hasattr(b, "text")) or "Analysis unavailable."
