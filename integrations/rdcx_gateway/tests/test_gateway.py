import base64
import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
os.environ.setdefault("RDCX_GATEWAY_AUTH_ENABLED", "false")
spec = importlib.util.spec_from_file_location("rdcx_gateway_under_test", ROOT / "gateway.py")
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.device = {
            "backend_type": "relay-ssh",
            "shell_kind": "posix",
            "capabilities": ["files"],
        }
        self.tenant = {"devices": ["test-linux"]}
        self.registry = {"devices": {"test-linux": self.device}}
        self.patches = [
            patch.object(
                gateway, "_principal", new=AsyncMock(return_value=("client", "tenant", self.tenant))
            ),
            patch.object(gateway, "_registry", return_value=self.registry),
            patch.object(gateway, "_audit"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    async def test_chunked_read_large_payload(self):
        data = b"A" * 75000
        calls = []

        async def fake_backend(_device, tool, arguments):
            self.assertEqual(tool, "shell_exec")
            args = arguments["command"].split()
            offset, size = map(int, args[-2:])
            calls.append((offset, size))
            return "[exit 0]\n" + base64.b64encode(data[offset : offset + size]).decode() + "\n"

        with patch.object(gateway, "_backend_call", new=fake_backend):
            result = await gateway.read_file("test-linux", "/tmp/fixture", 80000)
        self.assertEqual(result["content"], data.decode())
        self.assertFalse(result["truncated"])
        self.assertGreater(len(calls), 2)
        self.assertTrue(all(size <= 32768 for _, size in calls))

    async def test_local_large_read_uses_bounded_chunks(self):
        import json

        data = b"B" * 75000
        calls = []
        self.device["backend_type"] = "relay-local"

        async def fake_backend(_device, tool, arguments):
            self.assertEqual(tool, "shell_exec")
            env = json.loads(arguments["env_json"])
            offset, size = int(env["RDCX_OFFSET"]), int(env["RDCX_SIZE"])
            self.assertEqual(env["RDCX_PATH"], "/tmp/fixture")
            calls.append((offset, size))
            return "[exit 0]\n" + base64.b64encode(data[offset : offset + size]).decode() + "\n"

        with patch.object(gateway, "_backend_call", new=fake_backend):
            result = await gateway.read_file("test-linux", "/tmp/fixture", 80000)
        self.assertEqual(result["content"], data.decode())
        self.assertFalse(result["truncated"])
        self.assertGreater(len(calls), 2)
        self.assertTrue(all(size <= 32768 for _, size in calls))

    async def test_read_detects_truncation(self):
        async def fake_backend(_device, _tool, _arguments):
            return "[exit 0]\n" + base64.b64encode(b"abcdef").decode() + "\n"

        with patch.object(gateway, "_backend_call", new=fake_backend):
            result = await gateway.read_file("test-linux", "/tmp/fixture", 5)
        self.assertEqual(result["content"], "abcde")
        self.assertTrue(result["truncated"])

    async def test_missing_file_reports_error(self):
        with patch.object(
            gateway, "_backend_call", new=AsyncMock(return_value="[exit 1]\nNo such file")
        ):
            result = await gateway.read_file("test-linux", "/missing", 10)
        self.assertEqual(result["exit_code"], 1)
        self.assertIn("No such file", result["error"])

    async def test_denied_device(self):
        with self.assertRaises(PermissionError):
            await gateway.read_file("not-granted", "/etc/hostname", 50)

    async def test_write_rewrite_and_append_transfer(self):
        with tempfile.TemporaryDirectory() as directory:
            transfers = []

            async def fake_backend(_device, tool, arguments):
                if tool == "ssh_upload":
                    transfers.append(
                        (
                            arguments["remote_path"],
                            pathlib.Path(arguments["local_path"]).read_bytes(),
                        )
                    )
                    return "[exit 0]\ntransfer completed"
                return "[exit 0]\noperation completed"

            with (
                patch.object(gateway, "SPOOL_DIR", pathlib.Path(directory)),
                patch.object(gateway, "_backend_call", new=fake_backend),
            ):
                one = await gateway.write_file("test-linux", "/tmp/fixture", "hello", "rewrite")
                two = await gateway.write_file("test-linux", "/tmp/fixture", " world", "append")
                self.assertEqual(list(pathlib.Path(directory).iterdir()), [])
        self.assertEqual(one["exit_code"], 0)
        self.assertEqual(two["exit_code"], 0)
        self.assertEqual([blob for _, blob in transfers], [b"hello", b" world"])
        self.assertEqual(transfers[0][0], "/tmp/fixture")
        self.assertNotEqual(transfers[1][0], "/tmp/fixture")

    async def test_invalid_confirmation_is_rejected_before_backend(self):
        with self.assertRaises(ValueError):
            await gateway.confirm_elevated("not-a-token")

    async def test_invalid_write_mode_rejected(self):
        with self.assertRaises(ValueError):
            await gateway.write_file("test-linux", "/tmp/fixture", "data", "unsupported")


class BackendHealthTests(unittest.TestCase):
    def test_timeout_and_denial_are_offline(self):
        self.assertFalse(gateway._backend_healthy("[TIMEOUT after 20s]"))
        self.assertFalse(gateway._backend_healthy("[DENIED tier 2 (STATEFUL)]"))
        self.assertFalse(gateway._backend_healthy("[ERROR backend unavailable]"))
        self.assertFalse(gateway._backend_healthy("[exit 255]\nPermission denied"))

    def test_success_is_online(self):
        self.assertTrue(gateway._backend_healthy("[exit 0]\nserver ready"))
        self.assertTrue(gateway._backend_healthy("relay-shell ready"))


if __name__ == "__main__":
    unittest.main()
