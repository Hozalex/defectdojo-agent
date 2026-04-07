import asyncio
import logging
from pathlib import Path

import anthropic
import asyncpg

from db import search_infrastructure
from dojo import Finding, ScanContext, format_component, service_for_finding
from utils import redact

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
        parts.append(f"\nDescription:\n{redact(finding.description)[:800]}")
    if finding.mitigation:
        parts.append(f"\nScanner mitigation hint:\n{redact(finding.mitigation)[:400]}")
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


# Haiku pricing (per token). Update if model or pricing changes.
_COST_INPUT_PER_TOKEN  = 0.80 / 1_000_000   # $0.80 / 1M input tokens
_COST_OUTPUT_PER_TOKEN = 4.00 / 1_000_000   # $4.00 / 1M output tokens


async def analyze_finding(
    client: anthropic.AsyncAnthropic,
    finding: Finding,
    ctx: ScanContext,
    system_prompt: str,
    pool: asyncpg.Pool | None,
    infra_cache: dict[str, str] | None = None,
    infra_inflight: dict[str, asyncio.Task[str]] | None = None,
) -> tuple[str | None, int, int]:
    """Returns (analysis_text_or_None, total_input_tokens, total_output_tokens).

    Returns None (no AI analysis) when the service cannot be resolved — avoids
    the model asking clarifying questions without useful context.
    """
    if service_for_finding(finding) is None:
        logger.debug("service unknown for finding %r — skipping LLM", finding.title)
        return None, 0, 0

    tools = [_INFRA_TOOL] if pool is not None else []
    messages: list[dict] = [
        {"role": "user", "content": _format_finding(finding, ctx)},
    ]
    input_tokens = output_tokens = 0

    try:
        # Max 2 iterations: one tool call + one final answer.
        # search_infrastructure is only needed once per finding.
        for _ in range(2):
            kwargs: dict = dict(
                model="claude-haiku-4-5-20251001",
                max_tokens=512,
                system=system_prompt,
                messages=messages,
            )
            if tools:
                kwargs["tools"] = tools

            resp = await client.messages.create(**kwargs)
            input_tokens  += resp.usage.input_tokens
            output_tokens += resp.usage.output_tokens

            if resp.stop_reason == "end_turn":
                text = "".join(b.text for b in resp.content if hasattr(b, "text"))
                return text, input_tokens, output_tokens

            if resp.stop_reason == "tool_use":
                tool_results = []
                for block in resp.content:
                    if block.type == "tool_use" and block.name == "search_infrastructure":
                        svc = (block.input.get("service_name") or "").strip()
                        logger.debug("search_infrastructure(%r)", svc)
                        if not svc:
                            result = "No service_name provided."
                        elif infra_cache is None:
                            result = await search_infrastructure(pool, svc)
                        else:
                            cache_key = svc.lower()
                            result = infra_cache.get(cache_key)
                            if result is None:
                                if infra_inflight is None:
                                    result = await search_infrastructure(pool, svc)
                                else:
                                    task = infra_inflight.get(cache_key)
                                    owner = False
                                    if task is None:
                                        task = asyncio.create_task(search_infrastructure(pool, svc))
                                        infra_inflight[cache_key] = task
                                        owner = True
                                    try:
                                        result = await task
                                    finally:
                                        if owner:
                                            infra_inflight.pop(cache_key, None)
                                infra_cache[cache_key] = result
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

        text = "".join(b.text for b in resp.content if hasattr(b, "text")) or None
        return text, input_tokens, output_tokens

    except Exception:
        logger.exception("Analysis failed for finding %r", finding.title)
        return None, input_tokens, output_tokens
