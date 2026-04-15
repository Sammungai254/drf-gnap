"""
GNAP Authorization Server client (RFC 9635).

Handles the full grant lifecycle:
  1. Initial grant request  (§2)
  2. Grant continuation     (§5)
  3. Token introspection / rotation
  4. Token management (revocation, §6)

Designed to be used from DRF authentication classes, management commands,
and Open Payments client flows.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

from drf_gnap.exceptions import GNAPContinuationError, GNAPGrantError, GNAPTokenError
from drf_gnap.settings import gnap_settings

# ---------------------------------------------------------------------------
# Data classes representing GNAP protocol objects (RFC 9635)
# ---------------------------------------------------------------------------


class GrantStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    FINALIZED = "finalized"
    DENIED = "denied"


@dataclass
class AccessToken:
    """Represents a GNAP access token (RFC 9635 §3.2)."""

    value: str
    label: str | None = None
    manage_uri: str | None = None
    expires_in: int | None = None  # seconds
    issued_at: float = field(default_factory=time.time)
    key: dict[str, Any] | None = None  # bound key for PoP
    flags: list[str] = field(default_factory=list)

    @property
    def is_expired(self) -> bool:
        if self.expires_in is None:
            return False
        return time.time() > self.issued_at + self.expires_in

    @property
    def bearer(self) -> bool:
        return "bearer" in self.flags


@dataclass
class GrantResponse:
    """Parsed GNAP grant response (RFC 9635 §3)."""

    status: GrantStatus
    access_token: AccessToken | None = None
    interact: dict[str, Any] | None = None
    continue_: dict[str, Any] | None = None
    subject: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GrantResponse":
        token_data = data.get("access_token")
        token: AccessToken | None = None
        if isinstance(token_data, dict):
            token = AccessToken(
                value=token_data["value"],
                label=token_data.get("label"),
                manage_uri=token_data.get("manage"),
                expires_in=token_data.get("expires_in"),
                flags=token_data.get("flags", []),
            )

        # Determine status heuristically (AS may not always return 'status')
        if token:
            status = GrantStatus.FINALIZED
        elif data.get("interact"):
            status = GrantStatus.PENDING
        elif data.get("error"):
            status = GrantStatus.DENIED
        else:
            status = GrantStatus.APPROVED

        return cls(
            status=status,
            access_token=token,
            interact=data.get("interact"),
            continue_=data.get("continue"),
            subject=data.get("subject"),
            raw=data,
        )


# ---------------------------------------------------------------------------
# GNAP Client
# ---------------------------------------------------------------------------


class GNAPClient:
    """
    Async-capable GNAP client for interacting with an Authorization Server.

    Typical usage (resource server / Open Payments client)::

        client = GNAPClient()
        response = await client.request_grant(
            access=[{"type": "incoming-payment", "actions": ["create", "read"]}],
        )
        token = response.access_token
    """

    def __init__(
        self,
        as_url: str | None = None,
        client_key: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> None:
        self.as_url = (as_url or gnap_settings.AS_URL).rstrip("/")
        self.client_key = client_key or gnap_settings.CLIENT_KEY
        self.timeout = timeout or gnap_settings.AS_TIMEOUT

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def request_grant(
        self,
        access: list[dict[str, Any]],
        subject: dict[str, Any] | None = None,
        interact: dict[str, Any] | None = None,
        client_display: dict[str, Any] | None = None,
    ) -> GrantResponse:
        """
        Send an initial grant request to the AS (RFC 9635 §2).

        Args:
            access: List of access token request objects (§2.1).
            subject: Optional subject information request (§2.2).
            interact: Optional interaction request (§2.5).
            client_display: Optional client display metadata.

        Returns:
            GrantResponse with status and (if approved) access token.
        """
        payload: dict[str, Any] = {
            "access_token": {"access": access},
            "client": {
                "key": self.client_key,
                **({"display": client_display} if client_display else {}),
            },
        }
        if subject:
            payload["subject"] = subject
        if interact:
            payload["interact"] = interact

        return self._post_grant(payload)

    def continue_grant(
        self,
        continue_uri: str,
        continue_token: str,
        interact_ref: str | None = None,
    ) -> GrantResponse:
        """
        Continue an in-progress grant (RFC 9635 §5).

        Args:
            continue_uri: URI from the ``continue.uri`` field of the initial response.
            continue_token: Token from ``continue.access_token.value``.
            interact_ref: Interaction reference returned after user interaction.
        """
        payload: dict[str, Any] = {}
        if interact_ref:
            payload["interact_ref"] = interact_ref

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"GNAP {continue_token}",
        }

        try:
            with httpx.Client(timeout=self.timeout) as http:
                resp = http.post(continue_uri, json=payload, headers=headers)
            return self._parse_response(resp)
        except httpx.RequestError as exc:
            raise GNAPContinuationError(f"Grant continuation request failed: {exc}") from exc

    def rotate_token(self, manage_uri: str, current_token: str) -> AccessToken:
        """
        Rotate an access token via its management URI (RFC 9635 §6).
        """
        headers = {
            "Authorization": f"GNAP {current_token}",
        }
        try:
            with httpx.Client(timeout=self.timeout) as http:
                resp = http.post(manage_uri, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            token_data = data.get("access_token", data)
            return AccessToken(
                value=token_data["value"],
                expires_in=token_data.get("expires_in"),
                manage_uri=token_data.get("manage"),
                flags=token_data.get("flags", []),
            )
        except httpx.RequestError as exc:
            raise GNAPTokenError(f"Token rotation failed: {exc}") from exc

    def revoke_token(self, manage_uri: str, current_token: str) -> None:
        """Revoke an access token (RFC 9635 §6.1 DELETE)."""
        headers = {"Authorization": f"GNAP {current_token}"}
        try:
            with httpx.Client(timeout=self.timeout) as http:
                resp = http.delete(manage_uri, headers=headers)
            resp.raise_for_status()
        except httpx.RequestError as exc:
            raise GNAPTokenError(f"Token revocation failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post_grant(self, payload: dict[str, Any]) -> GrantResponse:
        headers = {
            "Content-Type": "application/json",
            "X-Request-ID": str(uuid.uuid4()),
        }
        try:
            with httpx.Client(timeout=self.timeout) as http:
                resp = http.post(self.as_url, json=payload, headers=headers)
            return self._parse_response(resp)
        except httpx.RequestError as exc:
            raise GNAPGrantError(f"Grant request failed: {exc}") from exc

    @staticmethod
    def _parse_response(response: httpx.Response) -> GrantResponse:
        try:
            data: dict[str, Any] = response.json()
        except json.JSONDecodeError as exc:
            raise GNAPGrantError(
                f"AS returned non-JSON response (HTTP {response.status_code}): {response.text[:200]}"
            ) from exc

        if response.status_code >= 400:
            error = data.get("error", {})
            code = error.get("code") if isinstance(error, dict) else str(error)
            description = error.get("description") if isinstance(error, dict) else response.text
            raise GNAPGrantError(
                f"AS error: {description}",
                error_code=code,
                status_code=response.status_code,
            )

        return GrantResponse.from_dict(data)