import asyncio
import logging

import asyncpg

logger = logging.getLogger(__name__)


async def create_pool(dsn: str, retries: int = 10, delay: float = 5.0) -> asyncpg.Pool:
    for attempt in range(1, retries + 1):
        try:
            pool = await asyncpg.create_pool(dsn, min_size=1, max_size=3)
            logger.info("Database connected")
            return pool
        except Exception as exc:
            if attempt == retries:
                raise
            logger.warning(
                "DB connect failed (attempt %d/%d): %s — retrying in %.0fs",
                attempt, retries, exc, delay,
            )
            await asyncio.sleep(delay)


async def search_infrastructure(
    pool: asyncpg.Pool,
    service_name: str,
    limit: int = 5,
) -> str:
    """Text search for k8s resources by service name.

    Prioritises Deployment and Ingress/HTTPRoute records to surface
    exposure context first.
    """
    rows = await pool.fetch(
        """
        SELECT kind, name, namespace, cluster, content
        FROM   infrastructure
        WHERE  name ILIKE $1 OR content ILIKE $1
        ORDER  BY CASE kind
            WHEN 'Deployment' THEN 1
            WHEN 'Ingress'    THEN 2
            WHEN 'HTTPRoute'  THEN 3
            WHEN 'Service'    THEN 4
            ELSE 5
        END
        LIMIT  $2
        """,
        f"%{service_name}%",
        limit,
    )
    if not rows:
        return f"No infrastructure records found for service '{service_name}'."

    lines: list[str] = []
    for row in rows:
        ns = f"/{row['namespace']}" if row["namespace"] else ""
        lines.append(f"[{row['cluster']}] {row['kind']} {row['name']}{ns}")
        lines.append(row["content"])
        lines.append("")
    return "\n".join(lines)
