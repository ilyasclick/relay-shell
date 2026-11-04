import asyncio
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("RDCX_GATEWAY_AUTH_ENABLED", "false")
spec = importlib.util.spec_from_file_location("rdcx_gateway_live", ROOT / "gateway.py")
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


@unittest.skipUnless(os.getenv("RDCX_GATEWAY_LIVE_LOCAL") == "1", "explicit local relay test only")
class LiveLocalBackendTests(unittest.IsolatedAsyncioTestCase):
    async def test_read_large_with_actual_local_relay(self):
        dev = {
            "backend_type": "relay-local",
            "backend_url": "http://127.0.0.1:8788/mcp",
            "shell_kind": "posix",
            "capabilities": ["files"],
        }
        tenant = {"devices": ["localhost"]}
        registry = {"devices": {"localhost": dev}}
        with patch.object(gateway, "_principal", new=AsyncMock(return_value=("test", "test", tenant))), \
             patch.object(gateway, "_registry", return_value=registry), \
             patch.object(gateway, "_audit"):
            result = await gateway.read_file("localhost", "/tmp/rdcx-hardening-large-20261104.txt", 80000)
        self.assertEqual(result["content"], "A" * 75000)
        self.assertFalse(result["truncated"])

if __name__ == "__main__":
    unittest.main()
