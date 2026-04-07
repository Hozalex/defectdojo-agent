import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    defectdojo_url: str         # internal API URL
    defectdojo_public_url: str  # public URL used in notification links
    defectdojo_api_key: str
    anthropic_api_key: str
    notify_url: str
    notify_format: str      # "slack" | "text"
    database_url: str | None
    extra_prompt_file: str | None
    log_level: str
    max_findings: int           # cap findings per notification
    llm_concurrency: int        # max parallel LLM requests per webhook
    ignore_scan_types: frozenset[str]  # scan types: send without AI analysis
    llm_enabled: bool           # set to False to disable AI analysis globally


def load() -> Config:
    defectdojo_url = os.environ["DEFECTDOJO_URL"].rstrip("/")
    raw_ignore = os.environ.get("IGNORE_SCAN_TYPES", "")
    ignore_scan_types = frozenset(s.strip() for s in raw_ignore.split(",") if s.strip())
    return Config(
        defectdojo_url=defectdojo_url,
        defectdojo_public_url=os.environ.get("DEFECTDOJO_PUBLIC_URL", defectdojo_url).rstrip("/"),
        defectdojo_api_key=os.environ["DEFECTDOJO_API_KEY"],
        anthropic_api_key=os.environ["ANTHROPIC_API_KEY"],
        notify_url=os.environ["NOTIFY_URL"],
        notify_format=os.environ.get("NOTIFY_FORMAT", "slack").lower(),
        database_url=os.environ.get("DATABASE_URL"),
        extra_prompt_file=os.environ.get("EXTRA_PROMPT_FILE"),
        log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        max_findings=int(os.environ.get("MAX_FINDINGS", "10")),
        llm_concurrency=max(1, int(os.environ.get("LLM_CONCURRENCY", "4"))),
        ignore_scan_types=ignore_scan_types,
        llm_enabled=os.environ.get("LLM_ENABLED", "true").lower() not in ("false", "0", "no"),
    )
