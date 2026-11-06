import base64
import importlib.util
import os
import pathlib
import unittest
from unittest.mock import AsyncMock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
os.environ.setdefault("RDCX_GATEWAY_AUTH_ENABLED", "false")
spec = importlib.util.spec_from_file_location("rdcx_gateway_windows_append", ROOT / "gateway.py")
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class WindowsAppendTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.device = {
            "backend_type": "relay-ssh",
            "shell_kind": "cmd",
            "capabilities": ["files"],
        }
        self.tenant = {"devices": ["win-test"]}
        self.registry = {"devices": {"win-test": self.device}}
        patches = [
            patch.object(
                gateway,
                "_principal",
                new=AsyncMock(return_value=("client", "tenant", self.tenant)),
            ),
            patch.object(gateway, "_registry", return_value=self.registry),
            patch.object(gateway, "_audit"),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    async def test_append_exact_utf8_bytes(self):
        commands = []

        async def backend(_device, tool, arguments):
            self.assertEqual(tool, "shell_exec")
            commands.append(arguments["command"])
            return "[exit 0]\nRDCX_APPENDED=6\n"

        with patch.object(gateway, "_backend_call", new=backend):
            result = await gateway.write_file("win-test", "C:\\\\Temp\\\\test.txt", "ééé", "append")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(len(commands), 1)
        self.assertIn("-EncodedCommand", commands[0])
        payload = commands[0].split("-EncodedCommand ", 1)[1]
        script = base64.b64decode(payload).decode("utf-16le")
        self.assertIn("RDCX_APPENDED=", script)
        self.assertIn(base64.b64encode("ééé".encode()).decode(), script)

    async def test_append_rejects_missing_confirmation(self):
        with (
            patch.object(gateway, "_backend_call", new=AsyncMock(return_value="[exit 0]\n")),
            self.assertRaises(RuntimeError),
        ):
            await gateway.write_file("win-test", "C:\\Temp\\test.txt", "x", "append")

    async def test_append_rejects_oversize_before_backend(self):
        with patch.object(gateway, "_backend_call", new=AsyncMock()) as backend:
            with self.assertRaises(ValueError):
                await gateway.write_file("win-test", "C:\\\\Temp\\\\test.txt", "x" * 4097, "append")
            backend.assert_not_awaited()

    async def test_append_rejects_metacharacters(self):
        with patch.object(gateway, "_backend_call", new=AsyncMock()) as backend:
            with self.assertRaises(ValueError):
                await gateway.write_file("win-test", "C:\\\\Temp\\\\bad&name", "x", "append")
            backend.assert_not_awaited()

    async def test_tenant_denied_before_backend(self):
        with patch.object(gateway, "_backend_call", new=AsyncMock()) as backend:
            with self.assertRaises(PermissionError):
                await gateway.write_file("not-granted", "C:\\\\Temp\\\\test.txt", "x", "append")
            backend.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
