"""Gateway-level Tier-3 negative and positive regression tests."""

import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
os.environ.setdefault("RDCX_GATEWAY_AUTH_ENABLED", "false")
spec = importlib.util.spec_from_file_location(
    "rdcx_tier3_entrypoints_under_test", ROOT / "gateway.py"
)
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)
ORIGINAL_REQUIRE_TIER3_BINDING = gateway._require_tier3_binding

ARMED = "[armed: re-issue the exact Tier-3 call now to execute it]"


class BrokerStub:
    def __init__(self, result=None, exception=None):
        self.result = result
        self.exception = exception
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def call_tool(self, name, args):
        self.calls.append((name, args))
        if self.exception:
            raise self.exception
        return self.result


class Tier3EntrypointTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.audit = Mock()
        self.stub = BrokerStub()
        self.patchers = [
            patch.object(
                gateway,
                "_principal",
                new=AsyncMock(return_value=("client-a", "personal", {"devices": ["test-host"]})),
            ),
            patch.object(gateway, "_audit", self.audit),
            patch.object(gateway, "_require_tier3_binding", new=AsyncMock()),
            patch.object(gateway, "Client", side_effect=lambda _url: self.stub),
        ]
        for p in self.patchers:
            p.start()
            self.addCleanup(p.stop)

    async def test_confirm_accepts_exact_broker_arm(self):
        self.stub.result = SimpleNamespace(is_error=False, structured_content={"result": ARMED})
        reply = await gateway.confirm_elevated("A" * 24)
        self.assertEqual(reply["result"], ARMED)
        self.assertEqual(self.stub.calls, [("operation_confirm", {"token": "A" * 24})])
        self.audit.assert_called_once_with("confirm_elevated", "personal", "client-a", None, "ok")

    async def test_confirm_rejects_ambiguous_non_error_response(self):
        for payload in ["", "ok", "true", "[armed]", ARMED + " suffix"]:
            with self.subTest(payload=payload):
                self.audit.reset_mock()
                self.stub.result = SimpleNamespace(
                    is_error=False, structured_content={"result": payload}
                )
                with self.assertRaisesRegex(PermissionError, "did not arm"):
                    await gateway.confirm_elevated("B" * 24)
                self.audit.assert_called_once_with(
                    "confirm_elevated", "personal", "client-a", None, "denied"
                )

    async def test_confirm_rejects_backend_error(self):
        self.stub.result = SimpleNamespace(is_error=True, structured_content={"result": ARMED})
        with self.assertRaisesRegex(PermissionError, "rejected confirmation"):
            await gateway.confirm_elevated("C" * 24)
        self.audit.assert_called_once_with(
            "confirm_elevated", "personal", "client-a", None, "denied"
        )

    async def test_confirm_records_backend_exception_as_error(self):
        self.stub.exception = RuntimeError("broker unavailable")
        with self.assertRaisesRegex(RuntimeError, "broker unavailable"):
            await gateway.confirm_elevated("D" * 24)
        self.audit.assert_called_once_with(
            "confirm_elevated", "personal", "client-a", None, "error"
        )

    async def test_confirm_invalid_token_never_calls_broker(self):
        with self.assertRaisesRegex(ValueError, "invalid confirmation token"):
            await gateway.confirm_elevated("short")
        self.assertEqual(self.stub.calls, [])

    async def test_both_privileged_entrypoints_fail_closed_before_broker(self):
        with patch.object(
            gateway,
            "_require_tier3_binding",
            new=AsyncMock(side_effect=PermissionError("unbound")),
        ):
            with self.assertRaisesRegex(PermissionError, "unbound"):
                await gateway.confirm_elevated("E" * 24)
            with self.assertRaisesRegex(PermissionError, "unbound"):
                await gateway.exec_elevated("test-host", "id -u")
        self.assertEqual(self.stub.calls, [])

    async def test_persisted_multi_client_identity_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "clients.json"
            path.write_text(
                json.dumps({"client-a": "personal", "client-b": "other"}),
                encoding="utf-8",
            )
            with (
                patch.object(gateway, "AUTH_ENABLED", True),
                patch.object(gateway, "AUTH_SINGLE_CLIENT", True),
                patch.object(gateway, "CLIENTS_PATH", path),
                self.assertRaisesRegex(PermissionError, "exactly one"),
            ):
                await ORIGINAL_REQUIRE_TIER3_BINDING(
                    "exec_elevated", "client-a", "personal", "test-host"
                )
        self.audit.assert_called_once_with(
            "exec_elevated", "personal", "client-a", "test-host", "denied"
        )

    async def test_exact_single_client_identity_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "clients.json"
            path.write_text(json.dumps({"client-a": "personal"}), encoding="utf-8")
            with (
                patch.object(gateway, "AUTH_ENABLED", True),
                patch.object(gateway, "AUTH_SINGLE_CLIENT", True),
                patch.object(gateway, "CLIENTS_PATH", path),
            ):
                await ORIGINAL_REQUIRE_TIER3_BINDING(
                    "exec_elevated", "client-a", "personal", "test-host"
                )
        self.audit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
