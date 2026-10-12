from __future__ import annotations

import ssl
import urllib.error
import urllib.request

from myownca.comms.base import DEFAULT_TIMEOUT_SECONDS, CommsError


def http_send(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    require_https: bool = True,
) -> tuple[int, str]:
    """Perform a single outbound HTTP(S) request via the stdlib (no extra deps).

    Returns ``(status_code, response_body)``. HTTP error statuses (4xx/5xx) are
    returned rather than raised; only transport-level failures raise CommsError.
    """
    if require_https and not url.lower().startswith("https://"):
        raise CommsError(f"Refusing to send over a non-HTTPS URL: {url}")
    request = urllib.request.Request(url, method=method.upper(), data=data, headers=headers or {})
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read().decode("utf-8", "replace")
            return response.status, body
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace") if exc.fp is not None else str(exc)
        return exc.code, detail
    except urllib.error.URLError as exc:
        raise CommsError(f"Request to {url} failed: {exc.reason}") from exc
    except (TimeoutError, OSError) as exc:
        raise CommsError(f"Request to {url} failed: {exc}") from exc
