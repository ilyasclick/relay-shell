"""Negative tests for the fail-closed Tier-3 identity boundary."""

from unittest import TestCase

from integrations.rdcx_gateway.tier3_binding import enforce_single_client_binding


class Tier3SingleClientBindingTests(TestCase):
    def test_auth_disabled_is_explicit_local_mode(self):
        enforce_single_client_binding(
            auth_enabled=False,
            single_client_mode=False,
            client_id="local-acceptance",
            tenant_id="personal",
            client_tenants={},
        )

    def test_multi_client_mapping_is_denied_even_when_flag_is_true(self):
        with self.assertRaisesRegex(PermissionError, "exactly one"):
            enforce_single_client_binding(
                auth_enabled=True,
                single_client_mode=True,
                client_id="client-a",
                tenant_id="tenant-a",
                client_tenants={"client-a": "tenant-a", "client-b": "tenant-b"},
            )

    def test_single_client_mode_flag_false_is_denied(self):
        with self.assertRaisesRegex(PermissionError, "client-bound"):
            enforce_single_client_binding(
                auth_enabled=True,
                single_client_mode=False,
                client_id="client-a",
                tenant_id="tenant-a",
                client_tenants={"client-a": "tenant-a"},
            )

    def test_wrong_client_or_tenant_is_denied(self):
        with self.assertRaises(PermissionError):
            enforce_single_client_binding(
                auth_enabled=True,
                single_client_mode=True,
                client_id="client-b",
                tenant_id="tenant-a",
                client_tenants={"client-a": "tenant-a"},
            )
        with self.assertRaises(PermissionError):
            enforce_single_client_binding(
                auth_enabled=True,
                single_client_mode=True,
                client_id="client-a",
                tenant_id="tenant-b",
                client_tenants={"client-a": "tenant-a"},
            )

    def test_exactly_one_bound_client_is_allowed(self):
        enforce_single_client_binding(
            auth_enabled=True,
            single_client_mode=True,
            client_id="client-a",
            tenant_id="tenant-a",
            client_tenants={"client-a": "tenant-a"},
        )
