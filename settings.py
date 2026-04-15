"""
Centralised settings for drf-gnap.

In your Django settings.py, configure via the GNAP dict:

    GNAP = {
        # Authorization Server grant endpoint
        "AS_URL": "https://auth.example.com/gnap",

        # Client key — either inline JWK dict or path to PEM file
        "CLIENT_KEY": {
            "kid": "my-key-1",
            "kty": "EC",
            "crv": "P-256",
            ...
        },

        # Algorithm used for HTTP Message Signatures (RFC 9421)
        # Options: "ecdsa-p256-sha256" | "rsa-pss-sha512" | "hmac-sha256" | "ed25519"
        "SIGNATURE_ALGORITHM": "ecdsa-p256-sha256",

        # Components to include in the signature base (RFC 9421 §2.1)
        "SIGNATURE_COMPONENTS": ["@method", "@target-uri", "content-digest", "authorization"],

        # Seconds before a signature expires (used in sig-params)
        "SIGNATURE_MAX_AGE": 300,

        # How long (seconds) to cache access tokens locally before re-negotiating
        "TOKEN_CACHE_TTL": 3600,

        # HTTP timeout for calls to the Authorization Server
        "AS_TIMEOUT": 10,

        # If True, attach Content-Digest header automatically on outgoing requests
        "AUTO_CONTENT_DIGEST": True,

        # Open Payments: resource server URL (Rafiki / Interledger)
        "OPEN_PAYMENTS_RS_URL": None,
    }
"""
from typing import Any

from django.conf import settings
from django.test.signals import setting_changed

DEFAULTS: dict[str, Any] = {
    "AS_URL": None,
    "CLIENT_KEY": None,
    "SIGNATURE_ALGORITHM": "ecdsa-p256-sha256",
    "SIGNATURE_COMPONENTS": [
        "@method",
        "@target-uri",
        "content-digest",
        "authorization",
    ],
    "SIGNATURE_MAX_AGE": 300,
    "TOKEN_CACHE_TTL": 3600,
    "AS_TIMEOUT": 10,
    "AUTO_CONTENT_DIGEST": True,
    "OPEN_PAYMENTS_RS_URL": None,
}

MANDATORY: list[str] = ["AS_URL", "CLIENT_KEY"]


class GNAPSettings:
    """
    Lazy settings object — reads from Django's GNAP dict on first access,
    merges with defaults, and validates mandatory keys.
    """

    def __init__(self) -> None:
        self._cache: dict[str, Any] = {}

    def _load(self) -> None:
        user_settings: dict[str, Any] = getattr(settings, "GNAP", {})
        merged = {**DEFAULTS, **user_settings}
        self._cache = merged

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        if not self._cache:
            self._load()
        if name not in self._cache:
            raise AttributeError(f"Invalid GNAP setting: '{name}'")
        return self._cache[name]

    def validate(self) -> None:
        """Call during app startup to fail fast on missing config."""
        if not self._cache:
            self._load()
        for key in MANDATORY:
            if not self._cache.get(key):
                raise ValueError(
                    f"GNAP['{key}'] is required. "
                    f"Add it to your Django settings GNAP dict."
                )

    def reload(self) -> None:
        self._cache = {}


gnap_settings = GNAPSettings()


def reload_settings(*args: Any, **kwargs: Any) -> None:
    setting = kwargs.get("setting")
    if setting == "GNAP":
        gnap_settings.reload()


setting_changed.connect(reload_settings)