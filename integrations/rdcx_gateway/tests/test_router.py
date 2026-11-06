import importlib.util
import os
import pathlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
os.environ.setdefault("RDCX_GATEWAY_AUTH_ENABLED", "false")
spec = importlib.util.spec_from_file_location("rdcx_router_under_test", ROOT / "gateway.py")
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class FakeRelay:
    def __init__(self, *_args, **_kwargs):
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def call_tool(self, name, args):
        self.calls.append((name, args))
        result = {
            "shell_spawn": "session TEST_SID started",
            "session_recv": "NDMS version 5.02\n(config)>",
            "session_kill": "stopped",
            "session_send": "sent",
        }.get(name, "ok")
        return SimpleNamespace(is_error=False, structured_content={"result": result})


class RouterBackendTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.device = {
            "backend_type": "netcraze-pty",
            "backend_url": "http://127.0.0.1:8788/mcp",
            "pty_wrapper": "/usr/local/bin/router-wrapper",
        }

    async def test_noninteractive_commands_denied(self):
        with self.assertRaises(PermissionError):
            await gateway._backend_call(self.device, "shell_exec", {"command": "show version"})
        with self.assertRaises(PermissionError):
            await gateway._backend_call(self.device, "ssh_upload", {"local_path": "/tmp/a", "remote_path": "/tmp/b"})

    async def test_arbitrary_terminal_input_denied(self):
        for data in ("configure terminal", "system configuration save", "show version; reboot", "show startup-config"):
            with self.subTest(data=data), self.assertRaises(PermissionError):
                await gateway._backend_call(self.device, "session_send", {"session_id": "s", "data": data, "enter": True})

    async def test_shell_spawn_must_use_wrapper(self):
        with self.assertRaises(PermissionError):
            await gateway._backend_call(self.device, "shell_spawn", {"command": "bash"})
        with self.assertRaises(PermissionError):
            await gateway._backend_call(self.device, "shell_spawn", {"cwd": "/tmp"})

    async def test_server_info_probes_and_cleans_session(self):
        client = FakeRelay()
        with patch.object(gateway, "Client", return_value=client):
            result = await gateway._backend_call(self.device, "server_info", {})
        self.assertIn("ROUTER_SSH_AUTH_OK", result)
        self.assertEqual(client.calls[0][0], "shell_spawn")
        self.assertEqual(client.calls[0][1]["command"], self.device["pty_wrapper"])
        self.assertEqual(client.calls[-1][0], "session_kill")

    async def test_allowed_read_only_terminal_command(self):
        client = FakeRelay()
        with patch.object(gateway, "Client", return_value=client):
            result = await gateway._backend_call(self.device, "session_send", {
                "session_id": "s", "data": "show version", "enter": True,
            })
        self.assertEqual(result, "sent")
        self.assertEqual(client.calls[0][0], "session_send")


if __name__ == "__main__":
    unittest.main()
