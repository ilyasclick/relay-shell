# RDCX Gate integration

This subdirectory contains the project-owned ChatGPT MCP gateway. The upstream `relay-shell` remains independent. Our gateway uses its execution/SSH/PTY/file transfer primitives while adding OAuth tenant mapping, device grants and audit attribution.

## Deployment

- Source: `gateway.py`, snapshot of the deployed custom gateway on 2026-11-04.
- Authorized deployment host: `code.tdrezerv.com`; production executable `/opt/rdcx-mcp/gateway.py`.
- Run from an isolated Python environment with the repository version of `relay-shell` and a compatible `mcp` package.
- Keep systemd units, Nginx configuration, registry, OAuth state, logs, certificates and secrets **on the server**. Do not commit these.
- Prior to deploying changes, capture a verified backup, current hashes, status and rollback script. Restart only after passing isolated tests, then repeat live ChatGPT connector acceptance.
- Preserve the privileged admin loopback isolation, Tier-3 confirmation, strict SSH host-key checking and unprivileged-only interactive PTY. Never add interactive root PTY.

## Tests

```sh
python -m unittest discover -s integrations/rdcx_gateway/tests -v
```

## Known limitations

- The file API is UTF-8 text, not a binary-safe transfer API; raw binary round trips are not supported via `read_file` or `write_file`.
- Windows `cmd.exe` and its PTY work; direct PowerShell over Windows OpenSSH timed out on 2026-11-04. Keep `cmd.exe` fallback.
- `tantal-dc` rejects the configured SSH key; authorized guest-side repair access is needed.
- OpenDesk is an optional GUI component and is not integrated or accepted.
- Production relay-shell is pinned at 0.5.0; the fork base is 0.5.2. Do not upgrade production without controlled rollback and live acceptance.
