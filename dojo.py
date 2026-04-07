import re
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

_TEST_ID_RE = re.compile(r"/test/(\d+)")


@dataclass
class Finding:
    id: int
    title: str
    severity: str           # "Critical" | "High"
    cve: str | None
    component_name: str | None
    component_version: str | None
    description: str
    mitigation: str | None
    file_path: str | None
    service: str | None     # set when DefectDojo service field is populated


@dataclass
class ScanContext:
    test_id: int
    test_url: str           # DefectDojo UI link
    scan_type: str          # e.g. "Trivy Scan", "Semgrep JSON Report"
    engagement_name: str    # e.g. "MR-413"
    product_name: str       # e.g. "backend-crm"


def service_for_finding(finding: Finding) -> str | None:
    """Resolve service name: explicit field first, then first path component."""
    if finding.service:
        return finding.service
    if finding.file_path:
        first = finding.file_path.split("/")[0]
        # Skip bare filenames (e.g. "pom.xml")
        if first and "." not in first:
            return first
    return None


def format_component(finding: Finding) -> str | None:
    if not finding.component_name:
        return None
    if finding.component_version:
        return f"{finding.component_name} {finding.component_version}"
    return finding.component_name


def parse_test_id(url_ui: str) -> int | None:
    """Extract test ID from a DefectDojo UI URL like https://dojo.example.com/test/69."""
    m = _TEST_ID_RE.search(url_ui)
    return int(m.group(1)) if m else None


class DojoClient:
    def __init__(self, base_url: str, api_key: str) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Token {api_key}"},
            timeout=30.0,
        )

    async def get_scan_context(self, test_id: int, test_url: str) -> ScanContext:
        resp = await self._client.get(f"/api/v2/tests/{test_id}/")
        resp.raise_for_status()
        test = resp.json()

        scan_type = test.get("test_type_name") or "Unknown Scan"
        engagement_id = test.get("engagement")
        engagement_name = test.get("engagement_name") or ""
        product_name = test.get("product_name") or ""

        # Older DefectDojo versions may not embed these — fall back to engagement API
        if engagement_id and not (engagement_name and product_name):
            try:
                eng_resp = await self._client.get(f"/api/v2/engagements/{engagement_id}/")
                eng_resp.raise_for_status()
                eng = eng_resp.json()
                engagement_name = engagement_name or eng.get("name") or ""
                product_name = product_name or eng.get("product_name") or ""
            except Exception:
                logger.warning("Failed to fetch engagement %s", engagement_id)

        return ScanContext(
            test_id=test_id,
            test_url=test_url,
            scan_type=scan_type,
            engagement_name=engagement_name,
            product_name=product_name,
        )

    async def get_findings(self, test_id: int) -> list[Finding]:
        resp = await self._client.get(
            "/api/v2/findings/",
            params={
                "test": test_id,
                "active": "true",
                "duplicate": "false",
                "severity": "Critical,High",
                "limit": 100,
            },
        )
        resp.raise_for_status()

        findings: list[Finding] = []
        for f in resp.json().get("results", []):
            findings.append(Finding(
                id=f["id"],
                title=f.get("title") or "",
                severity=f.get("severity") or "",
                cve=f.get("cve") or None,
                component_name=f.get("component_name") or None,
                component_version=f.get("component_version") or None,
                description=f.get("description") or "",
                mitigation=f.get("mitigation") or None,
                file_path=f.get("file_path") or None,
                service=f.get("service") or None,
            ))
        return findings

    async def close(self) -> None:
        await self._client.aclose()
