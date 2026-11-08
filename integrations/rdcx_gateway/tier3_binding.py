"""Fail-closed identity boundary for Gateway Tier-3 operations.

The current Gateway uses one shared administrative relay. Until the relay
propagates and verifies the original OAuth principal across challenge,
confirmation, and exact retry, authenticated Tier-3 access is restricted to
exactly one configured OAuth client. This is deliberately conservative:
multi-client Tier-3 is denied rather than treated as isolated.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def enforce_single_client_binding(
    *,
    auth_enabled: bool,
    single_client_mode: bool,
    client_id: str,
    tenant_id: str,
    client_tenants: Mapping[str, Any],
) -> None:
    """Allow only a verified single-client Tier-3 boundary.

    Raises PermissionError for every ambiguous or multi-client state.
    """
    if not auth_enabled:
        return
    if not single_client_mode:
        raise PermissionError(
            "Tier-3 requires a client-bound admin relay identity"
        )
    normalized = {
        str(key): str(value)
        for key, value in client_tenants.items()
        if str(key) and str(value)
    }
    if len(normalized) != 1:
        raise PermissionError(
            "Tier-3 is disabled unless exactly one OAuth client is configured"
        )
    if normalized.get(client_id) != tenant_id:
        raise PermissionError(
            "Tier-3 OAuth client is not bound to the active tenant"
        )
