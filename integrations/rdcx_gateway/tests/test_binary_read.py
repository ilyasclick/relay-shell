import base64
import hashlib
import unittest
from unittest.mock import AsyncMock, patch

from integrations.rdcx_gateway.binary_files import (
    CHUNK_LIMIT,
    decode_payload,
    parse_read_response,
    validate_range,
)
from integrations.rdcx_gateway.tests.test_gateway import gateway


class BinaryCodecTests(unittest.TestCase):
    def test_binary_bytes_and_hash(self):
        raw = bytes([0, 255, 128, 0, 13, 10])
        parsed = parse_read_response(base64.b64encode(raw).decode() + "\nTRUNCATED=1", len(raw))
        self.assertEqual(decode_payload(parsed["content_base64"]), raw)
        self.assertEqual(parsed["content_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertTrue(parsed["truncated"])

    def test_empty_and_bad_ack(self):
        self.assertEqual(parse_read_response("\nTRUNCATED=0", 1)["bytes_read"], 0)
        for value in ("", "!!!!\nTRUNCATED=0", "Zg==\nTRUNCATED=maybe",
                      "Zg==\nTRUNCATED=0\nextra", "Zg==\nTRUNCATED=0"):
            if value == "Zg==\nTRUNCATED=0":
                continue
            with self.subTest(value=value), self.assertRaises((ValueError, RuntimeError)):
                parse_read_response(value, 1)

    def test_range_and_noncanonical_base64(self):
        for offset, size in ((-1, 1), (1 << 53, 1), (0, 0), (0, CHUNK_LIMIT + 1), (True, 1)):
            with self.assertRaises(ValueError):
                validate_range(offset, size)
        for value in ("Zh==", "Zg", "Zg==\n", "A" * 44000):
            with self.assertRaises(ValueError):
                decode_payload(value)


class BinaryReadGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.device = {"backend_type": "relay-ssh", "shell_kind": "cmd", "capabilities": ["files"]}
        self.tenant = {"devices": ["allowed"]}
        self.registry = {"devices": {"allowed": self.device, "denied": self.device}}
        self.patches = [
            patch.object(
                gateway,
                "_principal",
                new=AsyncMock(return_value=("client", "tenant", self.tenant)),
            ),
            patch.object(gateway, "_registry", return_value=self.registry),
            patch.object(gateway, "_audit"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    async def test_windows_command_short_read_loop_and_exact_bytes(self):
        raw = bytes([0, 255, 128, 0])
        response = "[exit 0]\n" + base64.b64encode(raw).decode() + "\nTRUNCATED=0\n"
        with patch.object(
            gateway, "_backend_call", new=AsyncMock(return_value=response)
        ) as backend:
            result = await gateway.read_file_bytes("allowed", r"C:\Temp\fixture.bin", 5, 4)
        self.assertEqual(decode_payload(result["content_base64"]), raw)
        self.assertEqual(result["offset"], 5)
        self.assertEqual(result["content_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertIn("EncodedCommand", backend.await_args.args[2]["command"])
        encoded = backend.await_args.args[2]["command"].split("-EncodedCommand ")[1]
        script = base64.b64decode(encoded).decode("utf-16le")
        self.assertIn("while($got -lt $buf.Length)", script)
        self.assertIn("if($r -eq 0){break}", script)
        self.assertIn("$got+=$r", script)
        self.assertIn("New-Object byte[] ($n+1)", script)

    async def test_posix_and_empty(self):
        self.device["shell_kind"] = "posix"
        with patch.object(
            gateway,
            "_backend_call",
            new=AsyncMock(return_value="[exit 0]\n\nTRUNCATED=0\n"),
        ) as backend:
            result = await gateway.read_file_bytes("allowed", "/tmp/fixture.bin", 0, 1)
        self.assertEqual(result["bytes_read"], 0)
        self.assertIn("python3 -c", backend.await_args.args[2]["command"])

    async def test_acl_and_backend_denials(self):
        with patch.object(gateway, "_backend_call", new=AsyncMock()) as backend:
            with self.assertRaises(PermissionError):
                await gateway.read_file_bytes("denied", "/tmp/fixture")
            backend.assert_not_awaited()
        for response in ("[exit 1]\nfail", "[DENIED tier2]", "[TIMEOUT after 20s]"):
            with (
                patch.object(gateway, "_backend_call", new=AsyncMock(return_value=response)),
                self.assertRaises(RuntimeError),
            ):
                await gateway.read_file_bytes("allowed", "/tmp/fixture")

    async def test_invalid_inputs_do_not_call_backend(self):
        with patch.object(gateway, "_backend_call", new=AsyncMock()) as backend:
            for path, offset, size in (("", 0, 1), ("/tmp/a", -1, 1),
                                       ("/tmp/a", 0, 32769), ("/tmp/a", (1 << 53) - 1, 1)):
                with self.assertRaises(ValueError):
                    await gateway.read_file_bytes("allowed", path, offset, size)
            backend.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
