import base64
import hashlib
import unittest
from unittest.mock import AsyncMock, patch

from integrations.rdcx_gateway.binary_files import (
    CHUNK_LIMIT, decode_payload, parse_read_response, validate_range,
)
from integrations.rdcx_gateway.tests.test_gateway import gateway


class BinaryCodecTests(unittest.TestCase):
    def test_exact_bytes(self):
        raw = b"\x00\xff\x80\x00"
        self.assertEqual(decode_payload(base64.b64encode(raw).decode()), raw)

    def test_bad_base64(self):
        for value in ("!!!!", "Zg", "Zg==\n", "Zh==", "Zg===", "é", "A" * 44000):
            with self.subTest(value=value[:20]), self.assertRaises(ValueError):
                decode_payload(value)

    def test_limits(self):
        for offset, size in ((-1, 1), (1 << 53, 1), (0, 0), (0, 32769), (True, 1)):
            with self.assertRaises(ValueError):
                validate_range(offset, size)
        validate_range(0, CHUNK_LIMIT)

    def test_truncation_and_digest(self):
        raw = b"\x00\xff"
        encoded = base64.b64encode(raw).decode()
        out = parse_read_response(encoded + "\nTRUNCATED=1", 2)
        self.assertEqual(out["bytes_read"], 2)
        self.assertEqual(out["content_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertTrue(out["truncated"])
        with self.assertRaises(RuntimeError):
            parse_read_response(encoded + "\nTRUNCATED=0", 1)


class BinaryGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.device = {"backend_type": "relay-ssh", "shell_kind": "posix", "capabilities": ["files"]}
        self.tenant = {"devices": ["allowed"]}
        self.registry = {"devices": {"allowed": self.device, "denied": self.device}}
        self.patches = [
            patch.object(gateway, "_principal", new=AsyncMock(return_value=("client", "tenant", self.tenant))),
            patch.object(gateway, "_registry", return_value=self.registry),
            patch.object(gateway, "_audit"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    async def test_read_binary(self):
        raw = b"\x00\xff"
        response = "[exit 0]\n" + base64.b64encode(raw).decode() + "\nTRUNCATED=0\n"
        with patch.object(gateway, "_backend_call", new=AsyncMock(return_value=response)) as backend:
            out = await gateway.read_file_bytes("allowed", "/tmp/a", 0, 2)
        self.assertEqual(out["content_base64"], base64.b64encode(raw).decode())
        self.assertEqual(out["bytes_read"], 2)
        self.assertEqual(backend.await_count, 1)

    async def test_acl_denial_before_backend(self):
        with patch.object(gateway, "_backend_call", new=AsyncMock()) as backend:
            with self.assertRaises(PermissionError):
                await gateway.read_file_bytes("denied", "/tmp/a")
            backend.assert_not_awaited()

    async def test_remote_failure_closed(self):
        with patch.object(gateway, "_backend_call", new=AsyncMock(return_value="[exit 1]\nerror")):
            with self.assertRaises(RuntimeError):
                await gateway.read_file_bytes("allowed", "/tmp/a")

    async def test_windows_read_command(self):
        self.device["shell_kind"] = "cmd"
        with patch.object(gateway, "_backend_call", new=AsyncMock(return_value="[exit 0]\n\nTRUNCATED=0\n")) as backend:
            result = await gateway.read_file_bytes("allowed", r"C:\Temp\\a.bin", 0, 1)
        self.assertEqual(result["bytes_read"], 0)
        self.assertIn("EncodedCommand", backend.await_args.args[2]["command"])


    async def test_write_fail_closed_without_remote_side_effects(self):
        payload = base64.b64encode(b"\\x00\\xff").decode()
        with patch.object(gateway, "_backend_call", new=AsyncMock()) as backend:
            for kind in ("posix", "cmd", "powershell"):
                self.device["shell_kind"] = kind
                for mode in ("rewrite", "append"):
                    with self.subTest(kind=kind, mode=mode):
                        with self.assertRaisesRegex(NotImplementedError, "Binary write disabled"):
                            await gateway.write_file_bytes("allowed", "/tmp/test.bin", payload, mode)
            self.device["backend_type"] = "relay-local"
            with self.assertRaises(NotImplementedError):
                await gateway.write_file_bytes("allowed", "/tmp/test.bin", payload)
            backend.assert_not_awaited()

    async def test_write_denied_identity_before_remote_execution(self):
        with patch.object(gateway, "_backend_call", new=AsyncMock()) as backend:
            with self.assertRaises(PermissionError):
                await gateway.write_file_bytes("denied", "/tmp/test.bin", "")
            backend.assert_not_awaited()

    async def test_write_invalid_payload_rejected_without_remote_execution(self):
        with patch.object(gateway, "_backend_call", new=AsyncMock()) as backend:
            with self.assertRaises(ValueError):
                await gateway.write_file_bytes("allowed", "/tmp/test.bin", "not-base64!")
            backend.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
