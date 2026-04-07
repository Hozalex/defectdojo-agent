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
    max_findings: int       # cap findings per notification


def load() -> Config:
    defectdojo_url = os.environ["DEFECTDOJO_URL"].rstrip("/")
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
    )
