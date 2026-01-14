from dataclasses import dataclass, field  # noqa: F401
from typing import Any  # noqa: F401


@dataclass
class Context:
    user_id: str


def get_proxy():
    return Proxy()


class Proxy:
    def _handle_execute_query(self, keyspace, query, ctx):
        return "result"


def execute_query(
    keyspace: str,
    query: str,
    ctx: Context | None = None,
) -> str:
    """Executes a read-only (SELECT) query against the database."""
    # VULNERABLE: 'query' comes directly from parameter
    return get_proxy()._handle_execute_query(keyspace, query, ctx)


def execute_sql(
    project_id: str,
    query: str,
    credentials: Any,
    config: Any,
) -> dict:
    try:
        # ... dummy bq_client ...
        class BQ:
            def query_and_wait(self, q, project, max_results):
                return []

        bq_client = BQ()

        # VULNERABLE: 'query' comes directly from parameter
        row_iterator = bq_client.query_and_wait(  # noqa: F841
            query, project=project_id, max_results=100
        )
        return {"status": "SUCCESS", "rows": []}
    except Exception as ex:
        return {"status": "ERROR", "error_details": str(ex)}


def safe_query(keyspace: str):
    # SAFE: query is a constant literal
    query = "SELECT * FROM users"
    return get_proxy()._handle_execute_query(keyspace, query, None)
