from fastapi import Request
from starlette.concurrency import run_in_threadpool

from ..createAlert import log_alert
from ..eventsLogger import log_event
from .sql_injection import detect_sql_injection


def _log_match(request: Request, status_code: int, sources: list[str]) -> None:
    route = request.scope.get("route")
    http_request = f"{request.method} {route.path if route else '<unmatched>'}"
    ip_src = request.client.host if request.client else None
    message = f"Possible SQL injection in {', '.join(sources)}"
    log_event(
        event_type="sql_injection",
        status_code=status_code,
        message=message,
        ip_src=ip_src,
        http_request=http_request,
    )
    log_alert(
        rule="sql_injection",
        event_count=1,
        status=True,
        message=f"{message}: {http_request}",
        ip_src=ip_src,
    )


async def log_sql_injection_request(request: Request, call_next):
    sources = []
    if any(detect_sql_injection(value) for _, value in request.query_params.multi_items()):
        sources.append("query parameters")

    if request.method == "POST" and request.url.path.rstrip("/") in {"/login", "/register"}:
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if not content_type or content_type == "application/json" or content_type.endswith("+json"):
            try:
                data = await request.json()
            except ValueError:
                data = None
            if isinstance(data, dict):
                for field in ("username", "email", "password"):
                    value = data.get(field)
                    if isinstance(value, str) and detect_sql_injection(value):
                        sources.append(f"body.{field}")

    response = await call_next(request)
    if sources:
        await run_in_threadpool(_log_match, request, response.status_code, sources)
    return response
