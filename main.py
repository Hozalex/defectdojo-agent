import logging
import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass

import anthropic
import asyncpg
import uvicorn
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import JSONResponse

import config as cfg
from analyzer import analyze_finding, load_system_prompt, _COST_INPUT_PER_TOKEN, _COST_OUTPUT_PER_TOKEN
from db import create_pool
from dojo import DojoClient, parse_test_id
from notifier import Notifier

logger = logging.getLogger(__name__)


class _HealthFilter(logging.Filter):
    """Downgrade uvicorn access log records for GET /health to DEBUG."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if "GET /health " in msg:
            record.levelno = logging.DEBUG
            record.levelname = "DEBUG"
        return True


# ── App state ──────────────────────────────────────────────────────────────────

@dataclass
class _State:
    conf: cfg.Config
    dojo: DojoClient
    claude: anthropic.AsyncAnthropic
    notifier: Notifier
    pool: asyncpg.Pool | None
    system_prompt: str


_state: _State | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _state

    conf = cfg.load()
    logging.basicConfig(
        level=conf.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logging.getLogger("uvicorn.access").addFilter(_HealthFilter())
    logger.info("Starting vuln-agent")

    pool: asyncpg.Pool | None = None
    if conf.database_url:
        try:
            pool = await create_pool(conf.database_url)
            logger.info("Infrastructure search enabled")
        except Exception:
            logger.exception("DB connection failed — infrastructure search disabled")

    _state = _State(
        conf=conf,
        dojo=DojoClient(conf.defectdojo_url, conf.defectdojo_api_key),
        claude=anthropic.AsyncAnthropic(api_key=conf.anthropic_api_key),
        notifier=Notifier(conf.notify_url, conf.notify_format, conf.defectdojo_public_url),
        pool=pool,
        system_prompt=load_system_prompt(conf.extra_prompt_file),
    )

    yield

    await _state.dojo.close()
    await _state.notifier.close()
    if _state.pool:
        await _state.pool.close()
    logger.info("Shutdown complete")


app = FastAPI(lifespan=lifespan)


# ── Background processing ──────────────────────────────────────────────────────

async def _process(test_id: int, test_url: str) -> None:
    s = _state
    try:
        ctx = await s.dojo.get_scan_context(test_id, test_url)

        findings = await s.dojo.get_findings(test_id)

        if not findings:
            logger.info("test=%d: no active High/Critical findings, skipping", test_id)
            return

        total = len(findings)
        logger.info(
            "test=%d: %d findings — %s / %s / %s",
            test_id, total, ctx.product_name, ctx.engagement_name, ctx.scan_type,
        )

        # Critical first, then High; alphabetical within each group
        findings.sort(key=lambda f: (0 if f.severity.lower() == "critical" else 1, f.title))
        capped = findings[: s.conf.max_findings]

        use_llm = (
            s.conf.llm_enabled
            and ctx.scan_type not in s.conf.ignore_scan_types
        )
        if not s.conf.llm_enabled:
            logger.info("test=%d: LLM disabled globally", test_id)
        elif ctx.scan_type in s.conf.ignore_scan_types:
            logger.info("test=%d: scan type %r in ignore list — sending without AI analysis", test_id, ctx.scan_type)

        analyses: list[str | None] = [None] * len(capped)
        total_input = total_output = 0
        if use_llm:
            semaphore = asyncio.Semaphore(s.conf.llm_concurrency)
            infra_cache: dict[str, str] | None = {} if s.pool is not None else None
            infra_inflight: dict[str, asyncio.Task[str]] | None = {} if s.pool is not None else None

            async def _analyze_one(finding):
                async with semaphore:
                    try:
                        return await analyze_finding(
                            s.claude,
                            finding,
                            ctx,
                            s.system_prompt,
                            s.pool,
                            infra_cache,
                            infra_inflight,
                        )
                    except Exception:
                        logger.exception("analyze_finding raised for %r", finding.title)
                        return None, 0, 0

            tasks = [
                asyncio.create_task(_analyze_one(finding))
                for finding in capped
            ]
            results = await asyncio.gather(*tasks)
            for i, (text, inp, out) in enumerate(results):
                analyses[i] = text
                total_input += inp
                total_output += out

        cost = total_input * _COST_INPUT_PER_TOKEN + total_output * _COST_OUTPUT_PER_TOKEN
        logger.info(
            "test=%d: tokens input=%d output=%d cost=$%.5f",
            test_id, total_input, total_output, cost,
        )

        await s.notifier.send(ctx, capped, analyses, total)
        logger.info("test=%d: notification sent (%d/%d findings)", test_id, len(capped), total)

    except Exception:
        logger.exception("Failed to process test=%d", test_id)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks):
    body = await request.json()

    # DefectDojo may put the test URL in url_ui, url_api, or embedded in description.
    # Try each field in order until test_id is found.
    candidates = [
        body.get("url_ui", ""),
        body.get("url_api", ""),
        body.get("description", ""),
    ]
    test_id: int | None = None
    test_url: str = ""
    for candidate in candidates:
        test_id = parse_test_id(candidate)
        if test_id:
            test_url = candidate
            break

    if not test_id:
        # DefectDojo sends a verification ping when the webhook is first saved — no test_id present.
        logger.info("Webhook received but no test_id found (likely a verification ping), skipping")
        return JSONResponse({"ok": True})

    logger.info("Webhook received: test_id=%d", test_id)
    background_tasks.add_task(_process, test_id, test_url)
    return JSONResponse({"ok": True, "test_id": test_id})


@app.get("/health")
async def health():
    return {"ok": True, "db": _state.pool is not None if _state else False}


# ── Entrypoint ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_config=None)
