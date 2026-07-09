"""Small HTTP client for source collection.

The collectors use only the Python standard library so the knowledge-base
bootstrap remains easy to reproduce on a fresh machine.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_USER_AGENT = "MAS4MBTS-Knowledge-Collector/0.1"


@dataclass(frozen=True)
class HttpResponse:
    url: str
    status: int
    text: str
    headers: dict[str, str]


def fetch_text(url: str, timeout: int = 30) -> HttpResponse:
    request = Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
    try:
        with urlopen(request, timeout=timeout) as response:
            content = response.read().decode("utf-8")
            headers = {key.lower(): value for key, value in response.headers.items()}
            return HttpResponse(url=url, status=response.status, text=content, headers=headers)
    except HTTPError as exc:
        raise RuntimeError(f"HTTP error while fetching {url}: {exc.code} {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"Network error while fetching {url}: {exc.reason}") from exc


def fetch_json(url: str, timeout: int = 30) -> dict:
    response = fetch_text(url, timeout=timeout)
    return json.loads(response.text)


def fetch_bytes(url: str, timeout: int = 120) -> tuple[bytes, dict[str, str], int]:
    request = Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
    try:
        with urlopen(request, timeout=timeout) as response:
            content = response.read()
            headers = {key.lower(): value for key, value in response.headers.items()}
            return content, headers, response.status
    except HTTPError as exc:
        raise RuntimeError(f"HTTP error while fetching {url}: {exc.code} {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"Network error while fetching {url}: {exc.reason}") from exc
