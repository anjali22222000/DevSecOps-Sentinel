"""Helpers that keep secrets out of anything Sentinel stores or prints."""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def redact_url(url: str) -> str:
    """Hide credentials (user:pass@ or token@) and query strings in a URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable-url>"
    netloc = parts.netloc
    if "@" in netloc:
        netloc = "***@" + netloc.rsplit("@", 1)[1]
    query = "***" if parts.query else ""
    if netloc == parts.netloc and query == parts.query:
        return url
    return urlunsplit(parts._replace(netloc=netloc, query=query))
