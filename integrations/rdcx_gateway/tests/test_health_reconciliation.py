from __future__ import annotations
import unittest
from unittest.mock import AsyncMock, patch

from integrations.rdcx_gateway import gateway


class HealthReconciliationTests(unittest.IsolatedAsyncioTestCase):
    async def test_openssh_retry_requires_marker(self):
        device = {
            "ssh_engine": "openssh",
            "health_probe_attempts": 2,
            "health_probe_timeout": 10,
        }
        with patch.object(
            gateway, "_backend_call", new_callable=AsyncMock
        ) as backend:
            backend.side_effect = [
                "[TIMEOUT] temporary failure",
                "[exit 0]\nRDCX_SSH_STATUS_OK",
            ]
            info, online = await gateway._probe_device_health(device)
            self.assertTrue(online)
            self.assertIn("RDCX_SSH_STATUS_OK", info)
            self.assertEqual(backend.await_count, 2)
            self.assertEqual(backend.await_args_list[0].args[2], {"timeout": 10})

    async def test_openssh_no_marker_is_offline(self):
        with patch.object(
            gateway, "_backend_call", new_callable=AsyncMock
        ) as backend:
            backend.return_value = "[exit 0]\nno positive marker"
            _, online = await gateway._probe_device_health({
                "ssh_engine": "openssh",
                "health_probe_attempts": 1,
            })
            self.assertFalse(online)
            self.assertEqual(backend.await_count, 1)

    async def test_retries_bounded_and_fail_closed(self):
        with patch.object(
            gateway, "_backend_call", new_callable=AsyncMock
        ) as backend:
            backend.side_effect = RuntimeError("unreachable")
            _, online = await gateway._probe_device_health({
                "health_probe_attempts": 100,
                "health_probe_timeout": 999,
            })
            self.assertFalse(online)
            self.assertEqual(backend.await_count, 3)
            self.assertEqual(backend.await_args_list[0].args[2], {"timeout": 25})

    async def test_inventory_and_device_status_use_same_health_logic(self):
        device = {
            "display_name": "Windows fixture",
            "os": "Windows",
            "capabilities": ["shell"],
            "ssh_engine": "openssh",
            "health_probe_attempts": 2,
        }
        registry = {"devices": {"fixture-win": device}}
        tenant = {"devices": ["fixture-win"]}
        with (
            patch.object(
                gateway,
                "_principal",
                new=AsyncMock(return_value=("client", "personal", tenant)),
            ),
            patch.object(gateway, "_registry", return_value=registry),
            patch.object(gateway, "_audit"),
            patch.object(gateway, "_backend_call", new_callable=AsyncMock) as backend,
        ):
            backend.side_effect = [
                "no marker", "RDCX_SSH_STATUS_OK",
                "no marker", "RDCX_SSH_STATUS_OK",
            ]
            inventory = await gateway.list_devices()
            status = await gateway.device_status("fixture-win")
            self.assertTrue(inventory[0]["online"])
            self.assertTrue(status["online"])
            self.assertEqual(backend.await_count, 4)


if __name__ == "__main__":
    unittest.main()
