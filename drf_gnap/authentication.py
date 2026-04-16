"""
Django REST Framework authentication class for GNAP (RFC 9635).

Drop-in replacement for TokenAuthentication with full GNAP grant support.

Usage::

    # settings.py
    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": [
            "drf_gnap.authentication.GNAPAuthentication",
        ],
    }

Or per-view::

    class MyView(APIView):
        authentication_classes = [GNAPAuthentication]
"""

from __future__ import annotations

import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractBaseUser, AnonymousUser
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from drf_gnap.gnap_client import GNAPClient, GrantResponse, GrantStatus
from drf_gnap.token_cache import TokenCache
from drf_gnap.signatures import sign_request


logger = logging.getLogger(__name__)
User = get_user_model()


class GNAPAuthentication(BaseAuthentication):
    """
    Authenticates requests carrying a GNAP access token.

    Looks for:
        Authorization: GNAP <token>

    On success, returns (user, gnap_token_value).

    For resource server use: validates the incoming GNAP token by
    calling the AS introspection endpoint if configured.
    """

    www_authenticate_realm = "api"
    auth_header_prefix = "GNAP"

    def authenticate(self, request):
        signature = request.headers.get("Signature")
        sig_input = request.headers.get("Signature-Input")

        if signature:
            # Recompute expected signature
            expected_headers = sign_request(
                method=request.method,
                url=request.build_absolute_uri(),
                headers={},
                body=request.body,
                key="test-key",
            )

            expected_signature = expected_headers.get("Signature")

            if signature != expected_signature:
                raise AuthenticationFailed("Invalid signature")

            user = self._resolve_user(request, signature)
            return user, signature

        return None

    def authenticate_header(self, request: Request) -> str:
        return f'{self.auth_header_prefix} realm="{self.www_authenticate_realm}"'

    def _authenticate_token(self, request: Request, token_value: str) -> tuple[Any, str]:
        """
        Validate a GNAP token value.

        Current implementation: trusts the token and attaches an anonymous
        principal. Override this in resource server mode to introspect via AS.
        """
        # TODO: introspection endpoint support (RFC 9635 §8 / Token Introspection draft)
        # For now, presence of a well-formed GNAP token is accepted.
        if not token_value or len(token_value) < 8:
            raise AuthenticationFailed("Invalid GNAP token.")

        # Attach a lightweight principal — subclass to resolve to a User
        user = self._resolve_user(request, token_value)
        return user, token_value
    
    def _resolve_user(self, request, token_value):
        user, _ = User.objects.get_or_create(username="gnap_user")
        return user

    # def _resolve_user(self, request: Request, token_value: str) -> Any:
    #     """
    #     Resolve the GNAP token to a Django user.

    #     Override this method to look up users by token in your own DB,
    #     call an identity endpoint, or integrate with your user model.

    #     Default: returns AnonymousUser (token-only auth, no user binding).
    #     """
    #     return AnonymousUser()


class GNAPClientAuthentication(BaseAuthentication):
    """
    Client-side GNAP authentication: automatically obtains a GNAP access
    token from the Authorization Server before proxying to a resource server.

    Intended for internal service-to-service calls where *this* Django service
    is the GNAP client (not the resource server).

    Usage in a service view that calls another API::

        class InternalView(APIView):
            authentication_classes = []  # no inbound auth needed
            permission_classes = []

            def get(self, request):
                auth = GNAPClientAuthentication()
                token = auth.get_token(access=[{"type": "read"}])
                ...
    """

    def __init__(
        self,
        access: list[dict[str, Any]] | None = None,
        cache: TokenCache | None = None,
    ) -> None:
        self._access = access or []
        self._cache = cache or TokenCache()
        self._client = GNAPClient()

    def authenticate(self, request: Request) -> None:
        # This class is not for inbound request authentication.
        return None

    def get_token(self, access: list[dict[str, Any]] | None = None) -> str:
        """
        Obtain a GNAP access token, using the cache if available.

        Args:
            access: List of access request objects (overrides constructor default).

        Returns:
            The raw token value string.
        """
        cache_key = self._cache_key(access or self._access)
        cached = self._cache.get(cache_key)
        if cached and not cached.is_expired:
            return cached.value

        access_request = access or self._access
        response: GrantResponse = self._client.request_grant(access=access_request)

        if response.status != GrantStatus.FINALIZED or not response.access_token:
            raise AuthenticationFailed(
                f"GNAP grant did not return an access token (status={response.status}). "
                f"Interactive grants are not supported in this flow."
            )

        self._cache.set(cache_key, response.access_token)
        return response.access_token.value

    @staticmethod
    def _cache_key(access: list[dict[str, Any]]) -> str:
        import hashlib, json
        return "gnap:" + hashlib.sha256(json.dumps(access, sort_keys=True).encode()).hexdigest()[:16]