from __future__ import annotations
import asyncio
import shlex
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from integrations.rdcx_gateway import gateway


class ReleaseSecurityTests(unittest.IsolatedAsyncioTestCase):
    def _client(self, result, error=False):
        backend = MagicMock()
        backend.call_tool = AsyncMock(return_value=SimpleNamespace(
            structured_content={"result": result},
            is_error=error,
            content=[],
        ))
        context = MagicMock()
        context.__aenter__ = AsyncMock(return_value=backend)
        context.__aexit__ = AsyncMock(return_value=None)
        return context, backend

    async def test_tier3_shared_client_mode_denied_before_broker(self):
        with (
            patch.object(gateway, "AUTH_ENABLED", True),
            patch.object(gateway, "AUTH_SINGLE_CLIENT", False),
            patch.object(gateway, "_principal", new=AsyncMock(return_value=("client", "personal", {}))),
            patch.object(gateway, "_load_json", return_value={"client": "personal"}),
            patch.object(gateway, "_audit") as audit,
            patch.object(gateway, "Client") as broker,
        ):
            with self.assertRaises(PermissionError):
                await gateway.confirm_elevated("A" * 16)
            broker.assert_not_called()
            self.assertEqual(audit.call_args.args[-1], "denied")

    async def test_tier3_ambiguous_mapping_denied_before_broker(self):
        with (
            patch.object(gateway, "AUTH_ENABLED", True),
            patch.object(gateway, "AUTH_SINGLE_CLIENT", True),
            patch.object(gateway, "_principal", new=AsyncMock(return_value=("client", "personal", {}))),
            patch.object(gateway, "_load_json", return_value={"client": "personal", "other": "foreign"}),
            patch.object(gateway, "_audit"),
            patch.object(gateway, "Client") as broker,
        ):
            with self.assertRaises(PermissionError):
                await gateway.confirm_elevated("A" * 16)
            broker.assert_not_called()

    async def test_tier3_unauthorized_mapping_denied_before_broker(self):
        with (
            patch.object(gateway, "AUTH_ENABLED", True),
            patch.object(gateway, "AUTH_SINGLE_CLIENT", True),
            patch.object(gateway, "_principal", new=AsyncMock(return_value=("client", "personal", {}))),
            patch.object(gateway, "_load_json", return_value={"other": "personal"}),
            patch.object(gateway, "_audit"),
            patch.object(gateway, "Client") as broker,
        ):
            with self.assertRaises(PermissionError):
                await gateway.confirm_elevated("A" * 16)
            broker.assert_not_called()

    async def test_tier3_exact_ack_required(self):
        positive = "[armed: re-issue the exact Tier-3 call now to execute it]"
        for text, error, outcome in [
            (positive, False, "ok"),
            ("[exit 0]", False, "denied"),
            (positive + " extra", False, "denied"),
            (positive, True, "denied"),
        ]:
            with self.subTest(outcome=outcome, result=text, error=error):
                context, backend = self._client(text, error)
                with (
                    patch.object(gateway, "AUTH_ENABLED", True),
                    patch.object(gateway, "AUTH_SINGLE_CLIENT", True),
                    patch.object(gateway, "_principal", new=AsyncMock(return_value=("client", "personal", {}))),
                    patch.object(gateway, "_load_json", return_value={"client": "personal"}),
                    patch.object(gateway, "_audit") as audit,
                    patch.object(gateway, "Client", return_value=context),
                ):
                    if outcome == "ok":
                        result = await gateway.confirm_elevated("A" * 16)
                        self.assertEqual(result["result"], positive)
                    else:
                        with self.assertRaises(PermissionError):
                            await gateway.confirm_elevated("A" * 16)
                    self.assertEqual(audit.call_args.args[-1], outcome)
                    backend.call_tool.assert_awaited_once()

    async def test_tier3_transport_exception_audited_error(self):
        context, backend = self._client("", False)
        backend.call_tool.side_effect = RuntimeError("offline")
        with (
            patch.object(gateway, "AUTH_ENABLED", True),
            patch.object(gateway, "AUTH_SINGLE_CLIENT", True),
            patch.object(gateway, "_principal", new=AsyncMock(return_value=("client", "personal", {}))),
            patch.object(gateway, "_load_json", return_value={"client": "personal"}),
            patch.object(gateway, "_audit") as audit,
            patch.object(gateway, "Client", return_value=context),
        ):
            with self.assertRaises(RuntimeError):
                await gateway.confirm_elevated("A" * 16)
            self.assertEqual(audit.call_args.args[-1], "error")

    async def test_giga_allowlist_is_exact(self):
        device = {"backend_type": "netcraze-pty", "backend_url": "http://127.0.0.1:1/mcp"}
        with patch.object(gateway, "Client") as broker:
            for command in ["show log 101 once", "show log 3000 once", "show log 100 once; reboot", "system reboot"]:
                with self.subTest(command=command):
                    with self.assertRaises(PermissionError):
                        await gateway._backend_call(device, "session_send", {"data":command,"enter":True})
            broker.assert_not_called()
        context, backend = self._client("OK")
        with patch.object(gateway, "Client", return_value=context):
            value = await gateway._backend_call(device, "session_send", {"data":"show log 100 once", "enter":True})
        self.assertEqual(value, "OK")
        self.assertEqual(backend.call_tool.await_args.args[1]["data"], "show log 100 once")

    async def test_routeros_openssh_status_and_cwd_failclosed(self):
        dev = {"backend_type":"relay-ssh", "ssh_engine":"openssh", "shell_kind":"routeros",
               "ssh_host":"localhost", "ssh_user":"operator", "ssh_key_path":"/dev/null", "backend_url":"http://127.0.0.1:1/mcp"}
        context, backend = self._client("[exit 0]\nRDCX_SSH_STATUS_OK")
        with patch.object(gateway, "Client", return_value=context):
            await gateway._backend_call(dev, "server_info", {})
            command=backend.call_tool.await_args.args[1]["command"]
            self.assertIn(':put "RDCX_SSH_STATUS_OK"', shlex.split(command)[-1])
            with self.assertRaises(ValueError):
                await gateway._backend_call(dev, "shell_exec", {"command":"system resource print", "cwd":"/tmp"})
            self.assertEqual(backend.call_tool.await_count, 1)

    async def test_inventory_bounded_to_three_concurrent_probes(self):
        devices=[f"d{i}" for i in range(12)]
        reg={"devices":{x:{"display_name":x,"os":"test", "capabilities":["shell"]} for x in devices}}
        count=0
        maximum=0
        async def probe(dev):
            nonlocal count, maximum
            count+=1
            maximum=max(maximum,count)
            await asyncio.sleep(0.005)
            count-=1
            return "OK", True
        with (
            patch.object(gateway,"_principal",new=AsyncMock(return_value=("test","personal",{"devices":devices}))),
            patch.object(gateway,"_registry",return_value=reg),
            patch.object(gateway,"_probe_device_health",side_effect=probe),
            patch.object(gateway,"_audit"),
        ):
            result=await gateway.list_devices()
        self.assertEqual(len(result),12)
        self.assertEqual(maximum,3)

    async def test_windows_missing_file_returns_structured_failure(self):
        device={"backend_type":"relay-ssh","shell_kind":"cmd","capabilities":["files"]}
        with (
            patch.object(gateway,"_principal",new=AsyncMock(return_value=("client","personal",{"devices":["win"]}))),
            patch.object(gateway,"_registry",return_value={"devices":{"win":device}}),
            patch.object(gateway,"_backend_call",new=AsyncMock(side_effect=RuntimeError("FileNotFoundException"))),
            patch.object(gateway,"_audit") as audit,
        ):
            result=await gateway.read_file("win","C:\\Windows\\missing.tmp",64)
        self.assertEqual(result["exit_code"],1)
        self.assertEqual(result["error"],"Windows remote file read failed")
        self.assertEqual(audit.call_args.args[-2:],[ "error",1] if False else ("error",1))

    async def test_windows_binary_read_suppresses_powershell_progress(self):
        import base64
        device={"backend_type":"relay-ssh","shell_kind":"cmd","capabilities":["files"]}
        async def backend(_device,_tool,args):
            command=args["command"]
            self.assertIn("-EncodedCommand ",command)
            script=base64.b64decode(command.rsplit(" ",1)[1]).decode("utf-16le")
            self.assertIn("$ProgressPreference='SilentlyContinue';",script)
            return "[exit 0]\nYQ==\nTRUNCATED=0"
        with (
            patch.object(gateway,"_principal",new=AsyncMock(return_value=("client","personal",{"devices":["win"]}))),
            patch.object(gateway,"_registry",return_value={"devices":{"win":device}}),
            patch.object(gateway,"_backend_call",new=AsyncMock(side_effect=backend)),
            patch.object(gateway,"_audit"),
        ):
            result=await gateway.read_file_bytes("win","C:\\Windows\\win.ini",0,64)
        self.assertEqual(result["bytes_read"],1)
        self.assertEqual(base64.b64decode(result["content_base64"]),b"a")
        self.assertFalse(result["truncated"])


if __name__=="__main__":
    unittest.main()
