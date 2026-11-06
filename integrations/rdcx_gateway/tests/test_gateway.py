import base64
import importlib.util
import os
import pathlib
import re
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

    async def test_windows_bounded_read_of_large_remote_file(self):
        data = b"A" * 289792
        self.device["shell_kind"] = "cmd"
        calls = []

        async def fake_backend(_device, tool, arguments):
            self.assertEqual(tool, "shell_exec")
            encoded = arguments["command"].split(" -EncodedCommand ", 1)[1]
            script = base64.b64decode(encoded).decode("utf-16le")
            match = re.search(r"\$o=(\d+);\$n=(\d+);", script)
            self.assertIsNotNone(match)
            offset, size = map(int, match.groups())
            calls.append((offset, size))
            payload = base64.b64encode(data[offset : offset + size]).decode()
            return "[exit 0]\n#< CLIXML\nRDCX_BASE64=" + payload + "\n<Objs>progress</Objs>\n"

        with patch.object(gateway, "_backend_call", new=fake_backend):
            result = await gateway.read_file("test-linux", r"C:\Windows\System32\cmd.exe", 70000)
        self.assertEqual(result["content"], "A" * 70000)
        self.assertTrue(result["truncated"])
        self.assertEqual(calls, [(0, 32768), (32768, 32768), (65536, 4465)])
        self.assertTrue(all(size <= 32768 for _, size in calls))

    async def test_windows_small_and_empty_file_read(self):
        data = b"hello"
        self.device["shell_kind"] = "cmd"

        async def fake_backend(_device, _tool, arguments):
            encoded = arguments["command"].split(" -EncodedCommand ", 1)[1]
            script = base64.b64decode(encoded).decode("utf-16le")
            self.assertIn("$p='C:\\Users\\O''Connor\\test.txt'", script)
            return "[exit 0]\nRDCX_BASE64=" + base64.b64encode(data).decode() + "\n"

        with patch.object(gateway, "_backend_call", new=fake_backend):
            result = await gateway.read_file("test-linux", r"C:\Users\O'Connor\test.txt", 16)
        self.assertEqual(result["content"], "hello")
        self.assertFalse(result["truncated"])

    async def test_windows_bounded_read_reports_remote_errors(self):
        self.device["shell_kind"] = "cmd"
        with patch.object(
            gateway,
            "_backend_call",
            new=AsyncMock(return_value="[exit 1]\nFile not found"),
        ):
            result = await gateway.read_file("test-linux", r"C:\missing.txt", 16)
        self.assertEqual(result["exit_code"], 1)
        self.assertIn("File not found", result["error"])

    async def test_windows_read_rejects_unsafe_path_before_backend(self):
        self.device["shell_kind"] = "cmd"
        with patch.object(gateway, "_backend_call", new=AsyncMock()) as backend:
            with self.assertRaises(ValueError):
                await gateway.read_file("test-linux", r"C:\unsafe&name.txt", 16)
            backend.assert_not_called()

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
