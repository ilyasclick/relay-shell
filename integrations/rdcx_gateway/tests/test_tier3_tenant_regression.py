"""Isolated Tier-3 and OAuth-boundary regression tests; no live backend calls."""

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, patch

from relay_shell.broker import ConfirmationBroker

os.environ.setdefault("RDCX_GATEWAY_AUTH_ENABLED", "false")
_GATEWAY = Path(__file__).resolve().parents[1] / "gateway.py"
_spec = importlib.util.spec_from_file_location("rdcx_tier3_regression_gateway", _GATEWAY)
gateway = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gateway)


class BrokerIsolationTests(TestCase):
    def setUp(self):
        self.now = 100.0
        self.broker = ConfirmationBroker(ttl=10, clock=lambda: self.now)
        self.principal_a = "oauth-client-A"
        self.principal_b = "oauth-client-B"

    def test_different_authenticated_principal_cannot_arm_or_consume(self):
        operation = "device-A:cmd:cwd:timeout"
        token = self.broker.plan("shell_exec", operation, self.principal_a).token
        self.assertFalse(self.broker.arm(token, self.principal_b))
        self.assertFalse(self.broker.consume("shell_exec", operation, self.principal_b))
        self.assertTrue(self.broker.arm(token, self.principal_a))
        self.assertFalse(self.broker.consume("shell_exec", operation, self.principal_b))
        self.assertTrue(self.broker.consume("shell_exec", operation, self.principal_a))
        self.assertFalse(self.broker.consume("shell_exec", operation, self.principal_a))

    def test_exact_operation_binding_and_replay(self):
        original = "device-A:command:cwd=/safe:timeout=60"
        token = self.broker.plan("shell_exec", original, self.principal_a).token
        self.assertTrue(self.broker.arm(token, self.principal_a))
        for altered in (
            "device-B:command:cwd=/safe:timeout=60",
            "device-A:changed-command:cwd=/safe:timeout=60",
            "device-A:command:cwd=/other:timeout=60",
            "device-A:command:cwd=/safe:timeout=61",
        ):
            self.assertFalse(self.broker.consume("shell_exec", altered, self.principal_a))
        self.assertFalse(self.broker.consume("ssh_exec", original, self.principal_a))
        self.assertTrue(self.broker.consume("shell_exec", original, self.principal_a))
        self.assertFalse(self.broker.consume("shell_exec", original, self.principal_a))

    def test_expiry_denies_arm_and_execution(self):
        token = self.broker.plan("shell_exec", "original", self.principal_a).token
        self.now += 10
        self.assertFalse(self.broker.arm(token, self.principal_a))
        self.assertFalse(self.broker.consume("shell_exec", "original", self.principal_a))


class GatewayConfirmationTests(IsolatedAsyncioTestCase):
    async def test_strict_token_syntax_never_contacts_backend(self):
        for token in ("", "short", "x" * 257, "a" * 16 + "/", "a" * 16 + "\\n"):
            with patch.object(gateway, "Client") as backend:
                with self.assertRaises(ValueError):
                    await gateway.confirm_elevated(token)
                backend.assert_not_called()

    async def test_valid_fixture_is_forwarded_only_to_admin_and_audited(self):
        token = "FAKE_token_0123456789ABCDEF"
        response = SimpleNamespace(
            is_error=False,
            structured_content={
                "result": "[armed: re-issue the exact Tier-3 call now to execute it]"
            },
        )
        mock_client = AsyncMock()
        mock_client.call_tool.return_value = response
        context = AsyncMock()
        context.__aenter__.return_value = mock_client
        with (
            patch.object(
                gateway,
                "_principal",
                new=AsyncMock(
                    return_value=("oauth-client-A", "tenant-A", {"devices": ["device-A"]})
                ),
            ),
            patch.object(gateway, "Client", return_value=context) as factory,
            patch.object(gateway, "_audit") as audit,
        ):
            result = await gateway.confirm_elevated(token)
        self.assertIn("[armed:", result["result"])
        factory.assert_called_once()
        mock_client.call_tool.assert_awaited_once_with("operation_confirm", {"token": token})
        audit.assert_called_once_with("confirm_elevated", "tenant-A", "oauth-client-A", None, "ok")

    async def test_backend_error_is_not_success_or_execution(self):
        response = SimpleNamespace(is_error=True, content=["denied"], structured_content={})
        mock_client = AsyncMock()
        mock_client.call_tool.return_value = response
        context = AsyncMock()
        context.__aenter__.return_value = mock_client
        with (
            patch.object(
                gateway,
                "_principal",
                new=AsyncMock(return_value=("oauth-client-B", "tenant-B", {"devices": []})),
            ),
            patch.object(gateway, "Client", return_value=context),
            patch.object(gateway, "_audit") as audit,
            patch.object(gateway, "_backend_call") as execution,
        ):
            with self.assertRaises(RuntimeError):
                await gateway.confirm_elevated("FAKE_token_0123456789ABCDEF")
            execution.assert_not_called()
            audit.assert_not_called()
