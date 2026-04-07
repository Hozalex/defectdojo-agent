import logging

import httpx

from dojo import Finding, ScanContext, format_component, service_for_finding
from utils import redact

logger = logging.getLogger(__name__)

_SEVERITY_COLOR = {
    "critical": "#C0392B",
    "high":     "#E67E22",
}

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
}

_DESC_MAX = 400  # characters shown in Description field


def _color(severity: str) -> str:
    return _SEVERITY_COLOR.get(severity.lower(), "#95A5A6")


def _format_text(finding: Finding, analysis: str | None) -> str:
    """Build the attachment body rendered at full text size.

    First line is bold *[Severity] title* — this ensures the severity badge
    is prominent (the attachment `title` field renders at a smaller size in
    RocketChat and is used only as a short link to DefectDojo).
    """
    lines: list[str] = []

    # Bold header — visible at body text size
    emoji = _SEVERITY_EMOJI.get(finding.severity.lower(), "⚪")
    lines.append(f"*{emoji} [{finding.severity}] {finding.title}*")
    lines.append("")

    desc = redact((finding.description or "").strip())
    if desc:
        if len(desc) > _DESC_MAX:
            desc = desc[:_DESC_MAX].rstrip() + "…"
        lines.append(f"Description: {desc}")
    else:
        lines.append("Description: —")

    lines.append("")

    if analysis:
        lines.append(f"Analysis:\n{analysis.strip()}")
    else:
        lines.append("Analysis unavailable.")

    return "\n".join(lines)


def _build_slack_payload(
    ctx: ScanContext,
    findings: list[Finding],
    analyses: list[str | None],
    total_count: int,
    dojo_base_url: str,
) -> dict:
    header = f"{ctx.product_name} | {ctx.engagement_name} | {ctx.scan_type} | {total_count} findings"
    if total_count > len(findings):
        header += f" ({len(findings)} shown)"

    attachments = []
    for finding, analysis in zip(findings, analyses):
        fields = []
        svc = service_for_finding(finding) or ""
        if svc:
            fields.append({"title": "Service", "value": svc, "short": True})
        comp = format_component(finding)
        if comp:
            fields.append({"title": "Component", "value": comp, "short": True})

        attachments.append({
            "color":      _color(finding.severity),
            "title":      "→ DefectDojo",
            "title_link": f"{dojo_base_url}/finding/{finding.id}",
            "text":       _format_text(finding, analysis),
            "mrkdwn_in":  ["text"],
            "fields":     fields,
        })

    return {"text": header, "attachments": attachments}


def _build_text_payload(
    ctx: ScanContext,
    findings: list[Finding],
    analyses: list[str | None],
    total_count: int,
) -> dict:
    lines = [
        f"Security findings: {ctx.product_name} / {ctx.engagement_name}",
        f"Scan: {ctx.scan_type} | {total_count} findings",
        "",
    ]
    for finding, analysis in zip(findings, analyses):
        lines.append(_format_text(finding, analysis))
        lines.append("")
    return {"text": "\n".join(lines)}


class Notifier:
    def __init__(self, url: str, fmt: str, dojo_base_url: str) -> None:
        self._url = url
        self._fmt = fmt
        self._dojo_base_url = dojo_base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=15.0)

    async def send(
        self,
        ctx: ScanContext,
        findings: list[Finding],
        analyses: list[str | None],
        total_count: int,
    ) -> None:
        if self._fmt == "slack":
            payload = _build_slack_payload(ctx, findings, analyses, total_count, self._dojo_base_url)
        else:
            payload = _build_text_payload(ctx, findings, analyses, total_count)

        resp = await self._client.post(self._url, json=payload)
        resp.raise_for_status()
        logger.info("Notification sent (HTTP %s)", resp.status_code)

    async def close(self) -> None:
        await self._client.aclose()
