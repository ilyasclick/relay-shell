from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import secrets
import shlex
import time
from pathlib import Path
from typing import Any

from mcp import Client
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from relay_shell.auth import build_auth_settings
from relay_shell.auth.oauth import FileOAuthProvider

AUTH_ENABLED = os.getenv("RDCX_GATEWAY_AUTH_ENABLED", "true").lower() == "true"
ISSUER = os.getenv("RDCX_GATEWAY_ISSUER", "https://mcp.tdrezerv.com")
RESOURCE_URL = os.getenv("RDCX_GATEWAY_RESOURCE_URL", "https://mcp.tdrezerv.com/mcp")
AUTH_STATE_DIR = os.getenv("RDCX_GATEWAY_AUTH_STATE_DIR", "/var/lib/rdcx-mcp/oauth")
AUTH_SINGLE_CLIENT = os.getenv("RDCX_GATEWAY_AUTH_SINGLE_CLIENT", "true").lower() == "true"
AUTH_REQUIRE_APPROVAL = os.getenv("RDCX_GATEWAY_AUTH_REQUIRE_APPROVAL", "true").lower() == "true"
HOST = os.getenv("RDCX_GATEWAY_HOST", "127.0.0.1")
PORT = int(os.getenv("RDCX_GATEWAY_PORT", "8789"))
REGISTRY_PATH = Path(os.getenv("RDCX_GATEWAY_REGISTRY", "/etc/rdcx-mcp/registry.json"))
SESSIONS_PATH = Path(os.getenv("RDCX_GATEWAY_SESSIONS", "/var/lib/rdcx-mcp/sessions.json"))
CLIENTS_PATH = Path(os.getenv("RDCX_GATEWAY_CLIENTS", "/var/lib/rdcx-mcp/client-tenants.json"))
AUDIT_PATH = Path(os.getenv("RDCX_GATEWAY_AUDIT", "/var/log/rdcx-mcp/audit.jsonl"))
SPOOL_DIR = Path(os.getenv("RDCX_GATEWAY_SPOOL", "/var/lib/rdcx-spool"))
MAX_FILE_BYTES = 262144
_state_lock = asyncio.Lock()


def _load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def _save_json(path: Path, value: Any) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


def _registry() -> dict[str, Any]:
    return _load_json(REGISTRY_PATH, {})


def _audit(
    tool: str,
    tenant: str,
    client_id: str,
    device_id: str | None,
    outcome: str,
    exit_code: int | None = None,
) -> None:
    record = {
        "ts": time.time(),
        "tenant": tenant,
        "client_id": client_id,
        "tool": tool,
        "device_id": device_id,
        "outcome": outcome,
        "exit_code": exit_code,
    }
    with AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


async def _principal() -> tuple[str, str, dict[str, Any]]:
    reg = _registry()
    if not AUTH_ENABLED:
        tenant_id = reg.get("bootstrap_tenant", "personal")
        return "local-acceptance", tenant_id, reg["tenants"][tenant_id]
    token = get_access_token()
    if token is None:
        raise PermissionError("authentication required")
    client_id = token.client_id
    async with _state_lock:
        mappings = _load_json(CLIENTS_PATH, {})
        tenant_id = mappings.get(client_id)
        if tenant_id is None and not mappings and reg.get("bootstrap_tenant"):
            tenant_id = reg["bootstrap_tenant"]
            mappings[client_id] = tenant_id
            _save_json(CLIENTS_PATH, mappings)
        elif tenant_id is None:
            raise PermissionError("OAuth client is not assigned to an RDCX tenant")
    tenant = reg.get("tenants", {}).get(tenant_id)
    if tenant is None:
        raise PermissionError("tenant is not configured")
    return client_id, tenant_id, tenant


def _device_for(
    reg: dict[str, Any], tenant: dict[str, Any], device_id: str, capability: str | None = None
) -> dict[str, Any]:
    if device_id not in tenant.get("devices", []):
        raise PermissionError("device is not granted to this tenant")
    device = reg.get("devices", {}).get(device_id)
    if device is None:
        raise ValueError("unknown device")
    if capability and capability not in device.get("capabilities", []):
        raise PermissionError(f"device does not provide capability: {capability}")
    return device


def _powershell_encoded(command: str, executable: str = "powershell.exe") -> str:
    payload = base64.b64encode(command.encode("utf-16le")).decode("ascii")
    return (
        f"{executable} -NoLogo -NoProfile -NonInteractive "
        f"-InputFormat None -OutputFormat Text -EncodedCommand {payload}"
    )


async def _backend_call(device: dict[str, Any], tool: str, arguments: dict[str, Any]) -> str:
    backend_type = device.get("backend_type")
    target_tool = tool
    target_args = dict(arguments)

    if backend_type == "netcraze-pty":
        if tool == "server_info":
            # Authenticate through the same restricted relay used for real sessions.
            async with Client(device["backend_url"]) as client:
                spawn = await client.call_tool(
                    "shell_spawn",
                    {
                        "command": device["pty_wrapper"],
                        "cols": 100,
                        "rows": 32,
                    },
                )
                if spawn.is_error:
                    raise RuntimeError("router probe spawn refused")
                sid = _parse_session_id(str((spawn.structured_content or {}).get("result", "")))
                try:
                    banner = ""
                    for _ in range(4):
                        chunk = await client.call_tool(
                            "session_recv",
                            {
                                "session_id": sid,
                                "timeout": 1.5,
                                "max_bytes": 4096,
                            },
                        )
                        if chunk.is_error:
                            raise RuntimeError("router probe receive failed")
                        banner += str((chunk.structured_content or {}).get("result", ""))
                        if "(config)>" in banner:
                            break
                    if "(config)>" not in banner or not any(
                        word in banner for word in ("NDMS version", "KeeneticOS version")
                    ):
                        raise RuntimeError("router CLI authentication not confirmed")
                    return "[exit 0]\nROUTER_SSH_AUTH_OK"
                finally:
                    await client.call_tool(
                        "session_kill",
                        {
                            "session_id": sid,
                            "signal_name": "TERM",
                            "close": True,
                        },
                    )
        elif tool == "shell_spawn":
            if str(arguments.get("command", "")).strip() or str(arguments.get("cwd", "")).strip():
                raise PermissionError("router session command and cwd overrides forbidden")
            target_tool = "shell_spawn"
            target_args = {
                "command": device["pty_wrapper"],
                "cols": int(arguments.get("cols", 120)),
                "rows": int(arguments.get("rows", 40)),
            }
        elif tool == "session_send":
            data = str(arguments.get("data", ""))
            if not bool(arguments.get("enter", True)) or not re.fullmatch(
                r"(?:show (?:version|system|interface(?: [A-Za-z0-9_.-]+)?"
                r"|upnp redirect|device-list|ip arp|ipv6|ssh|sstp-server|\?)|\?|exit)",
                data,
            ):
                raise PermissionError("router CLI is restricted to read-only diagnostics")
        elif tool not in {"session_recv", "session_kill"}:
            raise PermissionError("router backend permits interactive PTY only")
    elif backend_type == "relay-ssh" and device.get("ssh_engine") == "openssh":
        host = device["ssh_host"]
        port = str(int(device.get("ssh_port", 22)))
        user = device.get("ssh_user", "")
        key_path = device.get("ssh_key_path", "")
        known_hosts = device.get("openssh_known_hosts", "/home/ilyas/.ssh/known_hosts")
        base_ssh = [
            "/usr/bin/ssh",
            "-F",
            "/home/ilyas/.ssh/config",
            "-i",
            key_path,
            "-o",
            "BatchMode=yes",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-p",
            port,
        ]

        if tool in {"ssh_upload", "ssh_download"}:
            timeout = int(arguments.get("timeout", 30))
            scp = [
                "/usr/bin/scp",
                "-q",
                "-F",
                "/home/ilyas/.ssh/config",
                "-P",
                port,
                "-i",
                key_path,
                "-o",
                "BatchMode=yes",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={known_hosts}",
            ]
            if tool == "ssh_upload":
                scp += [arguments["local_path"], f"{user}@{host}:{arguments['remote_path']}"]
            else:
                scp += [f"{user}@{host}:{arguments['remote_path']}", arguments["local_path"]]
            target_tool = "shell_exec"
            target_args = {"command": shlex.join(scp), "timeout": timeout + 5, "merge_stderr": True}
        elif tool in {"shell_exec", "server_info"}:
            timeout = int(arguments.get("timeout", 15))
            if tool == "server_info":
                remote_command = "cmd.exe /d /s /c echo RDCX_SSH_STATUS_OK"
            else:
                command = str(arguments.get("command", ""))
                cwd = str(arguments.get("cwd", ""))
                if device.get("shell_kind") == "cmd":
                    if cwd:
                        safe_cwd = cwd.replace('"', '""')
                        command = f'cd /d "{safe_cwd}" && {command}'
                    remote_command = f"cmd.exe /d /s /c {command}"
                else:
                    powershell_exe = device.get("powershell_path", "powershell.exe")
                    if cwd:
                        escaped = cwd.replace("'", "''")
                        command = f"Set-Location -LiteralPath '{escaped}'; {command}"
                    remote_command = _powershell_encoded(command, powershell_exe)
            target_tool = "shell_exec"
            target_args = {
                "command": shlex.join([*base_ssh, f"{user}@{host}", remote_command]),
                "timeout": timeout + 5,
                "merge_stderr": True,
            }
        elif tool == "shell_spawn":
            command = str(arguments.get("command", ""))
            cwd = str(arguments.get("cwd", ""))
            if device.get("shell_kind") == "cmd":
                if not command:
                    remote_command = "cmd.exe"
                else:
                    if cwd:
                        safe_cwd = cwd.replace('"', '""')
                        command = f'cd /d "{safe_cwd}" && {command}'
                    remote_command = f"cmd.exe /k {command}"
            else:
                powershell_exe = device.get("powershell_path", "powershell.exe")
                remote_command = f"{powershell_exe} -NoLogo -NoProfile"
            target_tool = "shell_spawn"
            target_args = {
                "command": shlex.join(
                    [
                        *base_ssh[:-2],
                        "-tt",
                        *base_ssh[-2:],
                        f"{user}@{host}",
                        remote_command,
                    ]
                ),
                "cols": int(arguments.get("cols", 120)),
                "rows": int(arguments.get("rows", 40)),
            }
        elif tool not in {"session_send", "session_recv", "session_kill"}:
            raise NotImplementedError(f"unsupported OpenSSH tool: {tool}")
    elif backend_type == "relay-ssh" and tool in {"ssh_upload", "ssh_download"}:
        target_tool = tool
        target_args = {
            "host": device["ssh_host"],
            "port": int(device.get("ssh_port", 0)),
            "user": device.get("ssh_user", ""),
            "key_path": device.get("ssh_key_path", ""),
            "known_hosts": "strict",
            **arguments,
        }
    elif backend_type == "relay-ssh" and tool in {"shell_exec", "shell_spawn", "server_info"}:
        target_tool = "ssh_exec" if tool in {"shell_exec", "server_info"} else "ssh_spawn"
        if tool == "server_info":
            command = (
                "echo RDCX_SSH_STATUS_OK"
                if device.get("shell_kind") == "cmd"
                else "printf RDCX_SSH_STATUS_OK"
            )
        else:
            command = str(arguments.get("command", ""))
        cwd = str(arguments.get("cwd", ""))
        if device.get("shell_kind") == "powershell":
            powershell_exe = device.get("powershell_path", "powershell.exe")
            if tool == "server_info":
                command = "Write-Output RDCX_SSH_STATUS_OK"
            if cwd:
                escaped = cwd.replace("'", "''")
                command = f"Set-Location -LiteralPath '{escaped}'; {command}"
            if tool == "shell_spawn":
                if command:
                    encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
                    command = (
                        f"{powershell_exe} -NoLogo -NoProfile -NoExit -EncodedCommand {encoded}"
                    )
                else:
                    command = f"{powershell_exe} -NoLogo -NoProfile"
            else:
                command = _powershell_encoded(command, powershell_exe)
        elif cwd:
            command = f"cd -- {shlex.quote(cwd)} && {command}"
        target_args = {
            "host": device["ssh_host"],
            "port": int(device.get("ssh_port", 0)),
            "user": device.get("ssh_user", ""),
            "key_path": device.get("ssh_key_path", ""),
            "known_hosts": "strict",
            "command": command,
        }
        if tool == "shell_exec":
            target_args["timeout"] = int(arguments.get("timeout", 0))
        elif tool == "shell_spawn":
            target_args["cols"] = int(arguments.get("cols", 120))
            target_args["rows"] = int(arguments.get("rows", 40))
    elif backend_type != "relay-local" and tool not in {
        "session_send",
        "session_recv",
        "session_kill",
    }:
        raise NotImplementedError("backend type is not implemented")
    async with Client(device["backend_url"]) as client:
        result = await client.call_tool(target_tool, target_args)
    if result.is_error:
        raise RuntimeError(str(result.content))
    text = str((result.structured_content or {}).get("result", ""))
    if device.get("ssh_engine") == "openssh" and target_tool == "shell_exec":
        code, body = _parse_exec(text)
        if code not in (None, 0):
            raise RuntimeError(body or text)
    return text


def _parse_exec(result: str) -> tuple[int | None, str]:
    m = re.match(r"^\[exit (-?\d+)\]\n?", result)
    return (int(m.group(1)), result[m.end() :]) if m else (None, result)


def _backend_healthy(result: str) -> bool:
    """Treat relay sentinel failures as offline, not successful transport."""
    response = result.lstrip()
    if response.startswith(
        ("[TIMEOUT", "[ERROR", "[DENIED", "[exit -", "[exit 1", "[exit 2", "[exit 3")
    ):
        return False
    exit_code, _ = _parse_exec(response)
    return exit_code in (None, 0)


def _parse_session_id(result: str) -> str:
    m = re.search(r"\bsession\s+([A-Za-z0-9_-]+)\s+started\b", result)
    if not m:
        raise RuntimeError(f"worker did not return a session id: {result[:160]}")
    return m.group(1)


def _session_record(
    public_id: str, sessions: dict[str, Any], client_id: str, tenant_id: str
) -> dict[str, Any]:
    rec = sessions.get(public_id)
    if rec is None:
        raise ValueError("unknown session")
    if rec.get("client_id") != client_id or rec.get("tenant") != tenant_id:
        raise PermissionError("session belongs to another identity")
    return rec


server_kwargs: dict[str, Any] = {
    "instructions": (
        "RDCX remote-control gateway. Call list_devices first. "
        "Use exec for one-shot commands and session_open/session_write/session_read "
        "for interactive workloads."
    )
}
if AUTH_ENABLED:
    server_kwargs["auth"] = build_auth_settings(ISSUER, RESOURCE_URL)
    server_kwargs["auth_server_provider"] = FileOAuthProvider(
        AUTH_STATE_DIR,
        single_client=AUTH_SINGLE_CLIENT,
        access_ttl=3600,
        refresh_ttl=2592000,
        code_ttl=300,
        resource_url=RESOURCE_URL,
        require_approval=AUTH_REQUIRE_APPROVAL,
    )
mcp = MCPServer("RDCX Gateway", **server_kwargs)


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
    )
)
async def get_profile() -> dict[str, Any]:
    """Return the authenticated RDCX profile identity and tenant label."""
    _, tenant_id, tenant = await _principal()
    return {"id": tenant["profile_id"], "tenant": tenant_id, "display_name": tenant["display_name"]}


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
    )
)
async def list_devices() -> list[dict[str, Any]]:
    """List devices granted to the authenticated tenant with stable IDs and capabilities."""
    client_id, tenant_id, tenant = await _principal()
    reg = _registry()
    out = []
    for device_id in tenant.get("devices", []):
        dev = reg["devices"][device_id]
        try:
            probe = await _backend_call(dev, "server_info", {})
            online = _backend_healthy(probe)
        # A failed backend probe must not mark a device as online.
        except Exception:  # noqa: BLE001
            online = False
        out.append(
            {
                "id": device_id,
                "display_name": dev["display_name"],
                "os": dev["os"],
                "online": online,
                "capabilities": dev.get("capabilities", []),
            }
        )
    _audit("list_devices", tenant_id, client_id, None, "ok")
    return out


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
    )
)
async def device_status(device_id: str) -> dict[str, Any]:
    """Return current status and capabilities for one granted device."""
    client_id, tenant_id, tenant = await _principal()
    reg = _registry()
    dev = _device_for(reg, tenant, device_id)
    try:
        info = await _backend_call(dev, "server_info", {})
        online = _backend_healthy(info)
    # Unknown backend exceptions must fail closed to offline.
    except Exception as exc:  # noqa: BLE001
        info, online = str(exc), False
    _audit("device_status", tenant_id, client_id, device_id, "ok" if online else "offline")
    return {
        "id": device_id,
        "display_name": dev["display_name"],
        "os": dev["os"],
        "online": online,
        "capabilities": dev.get("capabilities", []),
        "backend": info[:2000] if online else None,
    }


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False
    )
)
async def exec(device_id: str, command: str, cwd: str = "", timeout: int = 60) -> dict[str, Any]:
    """Run one command on a granted device through relay-shell."""
    client_id, tenant_id, tenant = await _principal()
    reg = _registry()
    dev = _device_for(reg, tenant, device_id, "shell")
    result = await _backend_call(
        dev,
        "shell_exec",
        {"command": command, "cwd": cwd, "timeout": timeout, "merge_stderr": True},
    )
    exit_code, output = _parse_exec(result)
    outcome = "ok" if exit_code == 0 else ("denied" if result.startswith("[DENIED") else "error")
    _audit("exec", tenant_id, client_id, device_id, outcome, exit_code)
    return {"device_id": device_id, "exit_code": exit_code, "output": output}


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False
    )
)
async def exec_elevated(
    device_id: str, command: str, cwd: str = "", timeout: int = 60
) -> dict[str, Any]:
    """Run one command through a bounded privileged administrative route.

    The target may use the loopback admin relay or a separately authorized identity.
    """
    client_id, tenant_id, tenant = await _principal()
    reg = _registry()
    dev = _device_for(reg, tenant, device_id, "elevated_shell")
    admin_dev = dict(dev)
    admin_dev["backend_url"] = dev.get("admin_backend_url") or os.getenv(
        "RDCX_GATEWAY_ADMIN_BACKEND_URL", "http://127.0.0.1:8792/mcp"
    )

    elevated_command = command
    if dev.get("backend_type") == "relay-local":
        pass
    elif dev.get("backend_type") == "relay-ssh":
        if dev.get("admin_ssh_user") and dev.get("admin_ssh_key_path"):
            admin_dev["ssh_user"] = dev["admin_ssh_user"]
            admin_dev["ssh_key_path"] = dev["admin_ssh_key_path"]
        elif dev.get("elevation_mode") == "sudo":
            if dev.get("shell_kind") not in (None, "posix"):
                raise PermissionError("sudo elevation is supported only for POSIX SSH targets")
            elevated_command = "sudo -n -- sh -lc " + shlex.quote(command)
        else:
            raise PermissionError("device has no configured administrative elevation path")
    else:
        raise PermissionError("device backend does not support elevated execution")

    result = await _backend_call(
        admin_dev,
        "shell_exec",
        {"command": elevated_command, "cwd": cwd, "timeout": timeout, "merge_stderr": True},
    )
    exit_code, output = _parse_exec(result)
    outcome = "ok" if exit_code == 0 else ("denied" if result.startswith("[DENIED") else "error")
    _audit("exec_elevated", tenant_id, client_id, device_id, outcome, exit_code)
    return {"device_id": device_id, "exit_code": exit_code, "output": output, "elevated": True}


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False
    )
)
async def confirm_elevated(token: str) -> dict[str, Any]:
    """Arm a pending Tier 3 confirmation token on the privileged admin relay."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", token):
        raise ValueError("invalid confirmation token format")
    client_id, tenant_id, _tenant = await _principal()
    admin_url = os.getenv("RDCX_GATEWAY_ADMIN_BACKEND_URL", "http://127.0.0.1:8792/mcp")
    async with Client(admin_url) as client:
        result = await client.call_tool("operation_confirm", {"token": token})
    if result.is_error:
        raise RuntimeError(str(result.content))
    text = str((result.structured_content or {}).get("result", ""))
    _audit("confirm_elevated", tenant_id, client_id, None, "ok")
    return {"result": text}


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False
    )
)
async def session_open(
    device_id: str, command: str = "", cwd: str = "", cols: int = 120, rows: int = 40
) -> dict[str, Any]:
    """Open a persistent PTY session owned by the authenticated identity."""
    client_id, tenant_id, tenant = await _principal()
    reg = _registry()
    dev = _device_for(reg, tenant, device_id, "pty")
    result = await _backend_call(
        dev, "shell_spawn", {"command": command, "cwd": cwd, "cols": cols, "rows": rows}
    )
    backend_id = _parse_session_id(result)
    public_id = "sess-" + secrets.token_hex(8)
    async with _state_lock:
        sessions = _load_json(SESSIONS_PATH, {})
        sessions[public_id] = {
            "client_id": client_id,
            "tenant": tenant_id,
            "device_id": device_id,
            "backend_session_id": backend_id,
            "created_at": time.time(),
        }
        _save_json(SESSIONS_PATH, sessions)
    _audit("session_open", tenant_id, client_id, device_id, "ok")
    return {"session_id": public_id, "device_id": device_id}


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=True, destructive_hint=False, idempotent_hint=False, open_world_hint=False
    )
)
async def session_read(
    session_id: str, timeout: float = 2.0, max_bytes: int = 65536
) -> dict[str, Any]:
    """Read incremental output from a PTY session owned by the authenticated identity."""
    client_id, tenant_id, tenant = await _principal()
    async with _state_lock:
        sessions = _load_json(SESSIONS_PATH, {})
        rec = _session_record(session_id, sessions, client_id, tenant_id)
    reg = _registry()
    dev = _device_for(reg, tenant, rec["device_id"], "pty")
    output = await _backend_call(
        dev,
        "session_recv",
        {
            "session_id": rec["backend_session_id"],
            "timeout": timeout,
            "max_bytes": max_bytes,
        },
    )
    _audit("session_read", tenant_id, client_id, rec["device_id"], "ok")
    return {"session_id": session_id, "output": output}


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False
    )
)
async def session_write(session_id: str, data: str, enter: bool = True) -> dict[str, Any]:
    """Send input to a PTY session owned by the authenticated identity."""
    client_id, tenant_id, tenant = await _principal()
    async with _state_lock:
        sessions = _load_json(SESSIONS_PATH, {})
        rec = _session_record(session_id, sessions, client_id, tenant_id)
    reg = _registry()
    dev = _device_for(reg, tenant, rec["device_id"], "pty")
    send_data = data
    send_enter = enter
    if dev.get("shell_kind") == "cmd" and enter:
        if not send_data.endswith("\r"):
            send_data += "\r"
        send_enter = False
    result = await _backend_call(
        dev,
        "session_send",
        {
            "session_id": rec["backend_session_id"],
            "data": send_data,
            "enter": send_enter,
        },
    )
    _audit("session_write", tenant_id, client_id, rec["device_id"], "ok")
    return {"session_id": session_id, "result": result}


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False
    )
)
async def session_close(session_id: str) -> dict[str, Any]:
    """Terminate and remove a PTY session owned by the authenticated identity."""
    client_id, tenant_id, tenant = await _principal()
    async with _state_lock:
        sessions = _load_json(SESSIONS_PATH, {})
        rec = _session_record(session_id, sessions, client_id, tenant_id)
    reg = _registry()
    dev = _device_for(reg, tenant, rec["device_id"], "pty")
    result = await _backend_call(
        dev,
        "session_kill",
        {
            "session_id": rec["backend_session_id"],
            "signal_name": "TERM",
            "close": True,
        },
    )
    async with _state_lock:
        sessions = _load_json(SESSIONS_PATH, {})
        sessions.pop(session_id, None)
        _save_json(SESSIONS_PATH, sessions)
    _audit("session_close", tenant_id, client_id, rec["device_id"], "ok")
    return {"session_id": session_id, "result": result}


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
    )
)
async def read_file(device_id: str, path: str, max_bytes: int = MAX_FILE_BYTES) -> dict[str, Any]:
    """Read a text file from a granted device with a bounded byte limit."""
    client_id, tenant_id, tenant = await _principal()
    reg = _registry()
    dev = _device_for(reg, tenant, device_id, "files")
    limit = max(1, min(int(max_bytes), MAX_FILE_BYTES))
    if dev.get("backend_type") == "relay-ssh" and dev.get("shell_kind") == "cmd":
        if any(ch in path for ch in '"&|<>^%!'):
            raise ValueError("Windows path contains unsupported shell metacharacters")
        collected = bytearray()
        while len(collected) <= limit:
            chunk_size = min(32768, limit + 1 - len(collected))
            escaped = path.replace("'", "''")
            script = (
                "$ErrorActionPreference='Stop';"
                "$ProgressPreference='SilentlyContinue';"
                f"$p='{escaped}';$o={len(collected)};$n={chunk_size};"
                "$f=[IO.File]::OpenRead($p);"
                "try{"
                "$null=$f.Seek($o,[IO.SeekOrigin]::Begin);"
                "$b=New-Object byte[] $n;$got=0;"
                "while($got -lt $n){"
                "$r=$f.Read($b,$got,$n-$got);if($r -eq 0){break};$got+=$r"
                "}"
                "}finally{$f.Dispose()};"
                "Write-Output ('RDCX_BASE64='+[Convert]::ToBase64String($b,0,$got))"
            )
            result = await _backend_call(
                dev,
                "shell_exec",
                {"command": _powershell_encoded(script), "timeout": 30},
            )
            exit_code, output = _parse_exec(result)
            if exit_code != 0:
                _audit("read_file", tenant_id, client_id, device_id, "error", exit_code)
                return {
                    "device_id": device_id,
                    "path": path,
                    "exit_code": exit_code,
                    "error": output,
                }
            markers = [
                line[len("RDCX_BASE64=") :]
                for line in output.splitlines()
                if line.startswith("RDCX_BASE64=")
            ]
            if len(markers) != 1:
                raise RuntimeError("Windows bounded read returned no unique data marker")
            chunk = base64.b64decode(markers[0], validate=True) if markers[0] else b""
            if len(chunk) > chunk_size:
                raise RuntimeError("Windows file read exceeded chunk size")
            collected.extend(chunk)
            if len(chunk) < chunk_size:
                break
        _audit("read_file", tenant_id, client_id, device_id, "ok", 0)
        return {
            "device_id": device_id,
            "path": path,
            "content": collected[:limit].decode("utf-8", errors="replace"),
            "truncated": len(collected) > limit,
        }
    if dev.get("backend_type") == "relay-ssh" and dev.get("shell_kind") not in {
        "cmd",
        "powershell",
    }:
        collected = bytearray()
        while len(collected) <= limit:
            chunk_size = min(32768, limit + 1 - len(collected))
            code = (
                "import sys,base64; f=open(sys.argv[1],'rb'); "
                "f.seek(int(sys.argv[2])); d=f.read(int(sys.argv[3])); f.close(); "
                "print(base64.b64encode(d).decode())"
            )
            result = await _backend_call(
                dev,
                "shell_exec",
                {
                    "command": (
                        f"python3 -c {shlex.quote(code)} {shlex.quote(path)} "
                        f"{len(collected)} {chunk_size}"
                    ),
                    "timeout": 30,
                },
            )
            exit_code, output = _parse_exec(result)
            if exit_code != 0:
                _audit("read_file", tenant_id, client_id, device_id, "error", exit_code)
                return {
                    "device_id": device_id,
                    "path": path,
                    "exit_code": exit_code,
                    "error": output,
                }
            lines = output.splitlines()
            chunk = base64.b64decode(lines[0], validate=True) if lines and lines[0] else b""
            if len(chunk) > chunk_size:
                raise RuntimeError("SSH file read exceeded chunk size")
            collected.extend(chunk)
            if len(chunk) < chunk_size:
                break
        _audit("read_file", tenant_id, client_id, device_id, "ok", 0)
        return {
            "device_id": device_id,
            "path": path,
            "content": collected[:limit].decode("utf-8", errors="replace"),
            "truncated": len(collected) > limit,
        }
    elif dev.get("backend_type") == "relay-local":
        collected = bytearray()
        while len(collected) <= limit:
            chunk_size = min(32768, limit + 1 - len(collected))
            code = (
                "import os,base64; p=os.environ['RDCX_PATH']; "
                "o=int(os.environ['RDCX_OFFSET']); n=int(os.environ['RDCX_SIZE']); "
                "f=open(p,'rb'); f.seek(o); data=f.read(n); f.close(); "
                "print(base64.b64encode(data).decode())"
            )
            result = await _backend_call(
                dev,
                "shell_exec",
                {
                    "command": f"python3 -c {shlex.quote(code)}",
                    "env_json": json.dumps(
                        {
                            "RDCX_PATH": path,
                            "RDCX_OFFSET": str(len(collected)),
                            "RDCX_SIZE": str(chunk_size),
                        }
                    ),
                    "timeout": 30,
                },
            )
            exit_code, output = _parse_exec(result)
            if exit_code != 0:
                _audit("read_file", tenant_id, client_id, device_id, "error", exit_code)
                return {
                    "device_id": device_id,
                    "path": path,
                    "exit_code": exit_code,
                    "error": output,
                }
            lines = output.splitlines()
            chunk = base64.b64decode(lines[0], validate=True) if lines and lines[0] else b""
            if len(chunk) > chunk_size:
                raise RuntimeError("local file read exceeded chunk size")
            collected.extend(chunk)
            if len(chunk) < chunk_size:
                break
        _audit("read_file", tenant_id, client_id, device_id, "ok", 0)
        return {
            "device_id": device_id,
            "path": path,
            "content": collected[:limit].decode("utf-8", errors="replace"),
            "truncated": len(collected) > limit,
        }
    elif dev.get("shell_kind") == "powershell":
        escaped = path.replace("'", "''")
        code = (
            f"$p='{escaped}'; $n={limit}; $fs=[IO.File]::OpenRead($p); "
            "$buf=New-Object byte[] ($n+1); "
            "try{$read=$fs.Read($buf,0,$buf.Length)}finally{$fs.Dispose()}; "
            "$take=[Math]::Min($read,$n); "
            "$slice=if($take -gt 0){[byte[]]$buf[0..($take-1)]}else{[byte[]]@()}; "
            "[Convert]::ToBase64String($slice); "
            "if($read -gt $n){'TRUNCATED=1'}else{'TRUNCATED=0'}"
        )
        result = await _backend_call(dev, "shell_exec", {"command": code, "timeout": 30})
    else:
        code = (
            "import os,base64; p=os.environ['RDCX_PATH']; n=int(os.environ['RDCX_MAX']); "
            "d=open(p,'rb').read(n+1); print(base64.b64encode(d[:n]).decode()); "
            "print('TRUNCATED='+('1' if len(d)>n else '0'))"
        )
        result = await _backend_call(
            dev,
            "shell_exec",
            {
                "command": f"python3 -c {json.dumps(code)}",
                "env_json": json.dumps({"RDCX_PATH": path, "RDCX_MAX": str(limit)}),
                "timeout": 30,
            },
        )
    exit_code, output = _parse_exec(result)
    if exit_code != 0:
        _audit("read_file", tenant_id, client_id, device_id, "error", exit_code)
        return {"device_id": device_id, "path": path, "exit_code": exit_code, "error": output}
    lines = output.splitlines()
    raw = base64.b64decode(lines[0]) if lines else b""
    truncated = any(line == "TRUNCATED=1" for line in lines[1:])
    _audit("read_file", tenant_id, client_id, device_id, "ok", exit_code)
    return {
        "device_id": device_id,
        "path": path,
        "content": raw.decode("utf-8", errors="replace"),
        "truncated": truncated,
    }


@mcp.tool(
    annotations=ToolAnnotations(
        read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False
    )
)
async def write_file(
    device_id: str, path: str, content: str, mode: str = "rewrite"
) -> dict[str, Any]:
    """Write UTF-8 text to a file on a granted device. mode is rewrite or append."""
    if mode not in {"rewrite", "append"}:
        raise ValueError("mode must be rewrite or append")
    data = content.encode("utf-8")
    client_id, tenant_id, tenant = await _principal()
    reg = _registry()
    dev = _device_for(reg, tenant, device_id, "files")
    max_write = 12000 if dev.get("shell_kind") == "powershell" else MAX_FILE_BYTES
    if len(data) > max_write:
        raise ValueError(f"content exceeds {max_write} bytes for this device")
    if dev.get("backend_type") == "relay-ssh" and dev.get("shell_kind") == "cmd":
        if mode != "rewrite":
            raise ValueError("append mode is not supported for SSH file transfer")
        tmp = SPOOL_DIR / ("upload-" + secrets.token_hex(12))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o660)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            tmp.chmod(0o660)
            transfer_path = (
                "/" + path.replace("\\", "/") if re.match(r"^[A-Za-z]:\\", path) else path
            )
            transfer = await _backend_call(
                dev,
                "ssh_upload",
                {"local_path": str(tmp), "remote_path": transfer_path, "timeout": 30},
            )
            if transfer.startswith("[ERROR"):
                raise RuntimeError(transfer)
        finally:
            tmp.unlink(missing_ok=True)
        _audit("write_file", tenant_id, client_id, device_id, "ok", 0)
        return {"device_id": device_id, "path": path, "exit_code": 0, "result": transfer}
    if dev.get("backend_type") == "relay-ssh" and dev.get("shell_kind") not in {
        "cmd",
        "powershell",
    }:
        tmp = SPOOL_DIR / ("upload-" + secrets.token_hex(12))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o660)
        remote_tmp = None
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            remote_path = path
            if mode == "append":
                remote_tmp = "/tmp/.rdcx-append-" + secrets.token_hex(16)
                create_code = (
                    "import os,sys; fd=os.open(sys.argv[1], "
                    "os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600); os.close(fd)"
                )
                created = await _backend_call(
                    dev,
                    "shell_exec",
                    {
                        "command": (
                            f"python3 -c {shlex.quote(create_code)} {shlex.quote(remote_tmp)}"
                        ),
                        "timeout": 15,
                    },
                )
                created_code, created_output = _parse_exec(created)
                if created_code != 0:
                    raise RuntimeError(created_output or created)
                remote_path = remote_tmp
            try:
                transfer = await _backend_call(
                    dev,
                    "ssh_upload",
                    {
                        "local_path": str(tmp),
                        "remote_path": remote_path,
                        "timeout": 45,
                    },
                )
                transfer_code, transfer_output = _parse_exec(transfer)
                if transfer_code not in (None, 0) or transfer.startswith(("[ERROR", "[DENIED")):
                    raise RuntimeError(transfer_output or transfer)
                result = transfer
                if mode == "append":
                    append_code = (
                        "import sys,shutil; "
                        "src=open(sys.argv[1],'rb'); dst=open(sys.argv[2],'ab'); "
                        "shutil.copyfileobj(src,dst); dst.close(); src.close()"
                    )
                    result = await _backend_call(
                        dev,
                        "shell_exec",
                        {
                            "command": f"python3 -c {shlex.quote(append_code)} "
                            f"{shlex.quote(remote_tmp)} {shlex.quote(path)}",
                            "timeout": 30,
                        },
                    )
                    append_code_exit, append_output = _parse_exec(result)
                    if append_code_exit != 0:
                        raise RuntimeError(append_output or result)
            finally:
                if remote_tmp is not None:
                    cleanup_code = (
                        "import os,sys; p=sys.argv[1]; os.unlink(p) if os.path.exists(p) else None"
                    )
                    await _backend_call(
                        dev,
                        "shell_exec",
                        {
                            "command": (
                                f"python3 -c {shlex.quote(cleanup_code)} {shlex.quote(remote_tmp)}"
                            ),
                            "timeout": 15,
                        },
                    )
        finally:
            tmp.unlink(missing_ok=True)
        _audit("write_file", tenant_id, client_id, device_id, "ok", 0)
        return {"device_id": device_id, "path": path, "exit_code": 0, "result": result}

    encoded = base64.b64encode(data).decode("ascii")
    if dev.get("shell_kind") == "powershell":
        escaped = path.replace("'", "''")
        if mode == "append":
            code = (
                f"$p='{escaped}'; $d=[Convert]::FromBase64String('{encoded}'); "
                "$f=[IO.File]::Open($p,[IO.FileMode]::Append,[IO.FileAccess]::Write); "
                "try{$f.Write($d,0,$d.Length)}finally{$f.Dispose()}; Write-Output $d.Length"
            )
        else:
            code = (
                f"$p='{escaped}'; $d=[Convert]::FromBase64String('{encoded}'); "
                "[IO.File]::WriteAllBytes($p,$d); Write-Output $d.Length"
            )
        result = await _backend_call(dev, "shell_exec", {"command": code, "timeout": 30})
    else:
        code = (
            "import os,sys,base64; p=os.environ['RDCX_PATH']; m=os.environ['RDCX_MODE']; "
            "d=base64.b64decode(sys.stdin.read()); f=open(p,'ab' if m=='append' else 'wb'); "
            "f.write(d); f.close(); print(len(d))"
        )
        result = await _backend_call(
            dev,
            "shell_exec",
            {
                "command": f"python3 -c {json.dumps(code)}",
                "env_json": json.dumps({"RDCX_PATH": path, "RDCX_MODE": mode}),
                "stdin": encoded,
                "timeout": 30,
            },
        )
    exit_code, output = _parse_exec(result)
    outcome = "ok" if exit_code == 0 else ("denied" if result.startswith("[DENIED") else "error")
    _audit("write_file", tenant_id, client_id, device_id, outcome, exit_code)
    return {"device_id": device_id, "path": path, "exit_code": exit_code, "result": output}


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host=HOST,
        port=PORT,
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
