"""
Token cache for GNAP access tokens.

Uses Django's cache framework (django.core.cache) so you can back it with
Redis, Memcached, or any other Django cache backend — no extra config needed.
Falls back to a simple in-memory dict if Django cache isn't available.
"""

from __future__ import annotations

from typing import Any

from drf_gnap.gnap_client import AccessToken
from drf_gnap.settings import gnap_settings


class TokenCache:
    """
    Thread-safe GNAP token cache.

    Stores AccessToken objects keyed by an arbitrary string.
    Expiry is governed by AccessToken.expires_in; the TTL stored in Django's
    cache is capped to GNAP["TOKEN_CACHE_TTL"] as a safety net.
    """

    def __init__(self, cache_alias: str = "default") -> None:
        self._cache_alias = cache_alias
        self._memory: dict[str, AccessToken] = {}

    def _backend(self) -> Any:
        try:
            from django.core.cache import caches
            return caches[self._cache_alias]
        except Exception:
            return None

    def get(self, key: str) -> AccessToken | None:
        backend = self._backend()
        if backend is not None:
            value: AccessToken | None = backend.get(f"drf_gnap:{key}")
            return value
        return self._memory.get(key)

    def set(self, key: str, token: AccessToken) -> None:
        ttl = min(
            token.expires_in or gnap_settings.TOKEN_CACHE_TTL,
            gnap_settings.TOKEN_CACHE_TTL,
        )
        backend = self._backend()
        if backend is not None:
            backend.set(f"drf_gnap:{key}", token, timeout=ttl)
        else:
            self._memory[key] = token

    def delete(self, key: str) -> None:
        backend = self._backend()
        if backend is not None:
            backend.delete(f"drf_gnap:{key}")
        else:
            self._memory.pop(key, None)

    def clear(self) -> None:
        backend = self._backend()
        if backend is not None:
            # Django doesn't have a prefix-delete; iterate in-memory fallback
            pass
        self._memory.clear()