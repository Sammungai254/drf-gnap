"""
Django middleware for automatic HTTP Message Signatures (RFC 9421).

GNAPSignatureMiddleware:
  - Optionally attaches Content-Digest to outgoing responses
  - Optionally verifies incoming Content-Digest on mutating requests
  - Designed for resource servers that require signed requests

Enable in settings::

    MIDDLEWARE = [
        ...
        "drf_gnap.middleware.GNAPSignatureMiddleware",
    ]
"""

from __future__ import annotations

import logging
from typing import Callable

from django.http import HttpRequest, HttpResponse

from drf_gnap.exceptions import GNAPSignatureError
from drf_gnap.signatures import compute_content_digest, verify_content_digest
from drf_gnap.settings import gnap_settings

logger = logging.getLogger(__name__)

MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class GNAPSignatureMiddleware:
    """
    Middleware that handles Content-Digest verification and generation.

    Configuration (all optional, defaults in gnap_settings):
        GNAP["AUTO_CONTENT_DIGEST"] = True   # attach digest to responses
        GNAP["VERIFY_INCOMING_DIGEST"] = False  # verify digest on inbound requests
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        self.auto_digest: bool = gnap_settings.AUTO_CONTENT_DIGEST

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # --- Inbound: verify Content-Digest if present ---
        if request.method in MUTATING_METHODS:
            digest_header = request.META.get("HTTP_CONTENT_DIGEST")
            if digest_header:
                try:
                    verify_content_digest(request.body, digest_header)
                except GNAPSignatureError as exc:
                    logger.warning("Content-Digest verification failed: %s", exc)
                    from django.http import JsonResponse
                    return JsonResponse(
                        {"error": "content_digest_mismatch", "detail": str(exc)},
                        status=400,
                    )

        response = self.get_response(request)

        # --- Outbound: attach Content-Digest to responses with a body ---
        if self.auto_digest and response.content:
            try:
                digest = compute_content_digest(response.content)
                response["Content-Digest"] = digest
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not attach Content-Digest: %s", exc)

        return response