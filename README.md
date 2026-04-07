# vuln-agent

Receives DefectDojo scan webhooks, analyzes High/Critical findings with Claude Haiku, and sends enriched security reports to a configurable webhook endpoint.

```
DefectDojo webhook (scan added)
    → POST /webhook
    → GET /api/v2/findings/?test=<id>&active=true&duplicate=false&severity=Critical,High
    → Claude Haiku — exploitability analysis
    → POST NOTIFY_URL (Slack attachment format)
```

## Configuration

### Required

| Variable | Description |
|---|---|
| `DEFECTDOJO_URL` | DefectDojo base URL |
| `DEFECTDOJO_API_KEY` | DefectDojo API token |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `NOTIFY_URL` | Webhook destination for reports |

### Optional

| Variable | Default | Description |
|---|---|---|
| `DEFECTDOJO_PUBLIC_URL` | `DEFECTDOJO_URL` | Public-facing URL used for finding links in notifications. Set when `DEFECTDOJO_URL` is an internal address |
| `DATABASE_URL` | — | PostgreSQL DSN. Enables `search_infrastructure` tool — Claude can query infra context before assessing risk |
| `EXTRA_PROMPT_FILE` | — | Path to a file appended to the system prompt at startup |
| `NOTIFY_FORMAT` | `slack` | `slack` (attachments) or `text` |
| `MAX_FINDINGS` | `10` | Maximum findings per notification, Critical first |
| `LLM_CONCURRENCY` | `4` | Maximum parallel Claude requests per webhook |
| `IGNORE_SCAN_TYPES` | — | Comma-separated scan type names to skip entirely, e.g. `Gitleaks Scan,DAST Scan` |
| `LOG_LEVEL` | `INFO` | Log level |

## Webhook

DefectDojo must be configured to POST scan notifications to `/webhook`.

Expected payload:
```json
{
  "description": "...",
  "url_ui": "https://dojo.example.com/test/69"
}
```

`test_id` is extracted from `url_ui` via `/test/(\d+)`. The endpoint returns `200` immediately; processing happens in the background.

## Service identification

For each finding, the service name is resolved in this order:

1. `finding.service` — populated when the scan was imported with a `service` parameter
2. First path component of `finding.file_path` — e.g. `payment-service/src/Foo.java` → `payment-service`
3. No service — AI analysis is skipped for this finding (sent as "Analysis unavailable")

## Infrastructure search (optional)

When `DATABASE_URL` is set, Claude receives the `search_infrastructure` tool and calls it before assessing risk. The tool does a text search against a `infrastructure` table:

```sql
SELECT kind, name, namespace, cluster, content
FROM infrastructure
WHERE name ILIKE '%<service>%' OR content ILIKE '%<service>%'
ORDER BY kind  -- Deployment, Ingress, HTTPRoute, Service first
LIMIT 5
```

The table is expected to contain Kubernetes resource records with a `content` text column describing each resource. The tool is intentionally simple — no embeddings or vector search required.

## Prompt extension

The built-in system prompt covers the generic analysis task only. Environment-specific context (infrastructure topology, service naming conventions, custom rules) is injected at deploy time:

```
EXTRA_PROMPT_FILE=/app/config/extra_prompt.txt
```

The file content is appended to the system prompt at startup. Mount it from a ConfigMap, secret, or volume.

## Notification format

Reports use a Slack-compatible payload compatible with Slack, RocketChat, and similar incoming webhook endpoints.

One message per scan, one attachment per finding:

```
my-repo | MR-42 | Trivy Scan | 14 findings (3 shown)

[Critical] CVE-2024-1234 — log4j-core 2.14.0
  Risk: High — public ingress detected, RCE via JNDI lookup is feasible without authentication.
  Remediation: upgrade log4j-core to 2.17.1+
  Service: payment-service | Component: log4j-core 2.14.0 | CVE: CVE-2024-1234

[High] ...
```

Set `NOTIFY_FORMAT=text` for plain-text output.

## Running locally

```bash
export DEFECTDOJO_URL=https://dojo.example.com
export DEFECTDOJO_API_KEY=...
export ANTHROPIC_API_KEY=...
export NOTIFY_URL=http://localhost:8081/webhook

pip install -r requirements.txt
python main.py
```

## Building

```bash
docker build -t vuln-agent:latest .
```
