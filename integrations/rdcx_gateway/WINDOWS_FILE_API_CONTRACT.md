# RDCX Windows append and binary transfer contract (draft)

## Implemented in this branch

- `write_file(device_id, path, content, mode="append")` accepts at most 4096 UTF-8 bytes for Windows `relay-ssh` / `cmd` targets. It encodes the payload in a bounded PowerShell `-EncodedCommand` and uses a .NET FileStream with `FileMode.Append`, `FileAccess.Write`, and a `finally` disposal.
- Device authorization is performed by the existing `_principal` / `_device_for(..., "files")` checks before backend invocation. Windows metacharacter filtering remains in place; the path is quoted as a PowerShell literal. Errors and absent exact byte-count acknowledgements fail closed. `rewrite` remains on the existing SCP path.
- This does **not** claim atomic append on network interruption. If a remote write succeeds but acknowledgement is lost, a retry can duplicate data; callers must reconcile content before retry.
- This branch does not modify the existing bounded Windows read fix in PR #1, and is not deployed.

## Proposed binary-safe API, not yet implemented

Keep existing text `read_file` / `write_file` signatures and behavior unchanged for backward compatibility. Introduce two distinct tools, `read_file_bytes(device_id, path, offset=0, max_bytes=32768)` and `write_file_bytes(device_id, path, content_base64, mode="rewrite", expected_sha256=None)`, rather than overloading UTF-8 text parameters.

- Validate device grant and `files` capability before touching paths. Enforce maximum 32768 raw bytes per read response and 32768 decoded bytes per write call, strict RFC 4648 base64 decoding (`validate=True`), input encoded-size cap, nonnegative bounded offsets, and total transfer quotas. Never decode binary data using `errors="replace"`.
- Read `max_bytes + 1` bytes, return exact `bytes_read`, `truncated`, `content_base64`, and `sha256` for the returned bytes. A complete-file hash must be clearly distinguished from a chunk hash. A missing file is an error, not an empty file.
- On Windows OpenSSH/cmd use a bounded PowerShell/.NET file-range read with byte-exact base64 output. On Linux SSH use bounded Python `rb` chunks. Avoid whole-file downloads. Limit backend command output below the relay 65536-character ceiling.
- For writes, stage each chunk under a unique tenant-isolated 0600 spool name, validate hash before commit, use a no-follow/symlink-safe destination policy, preserve exact append semantics, and guarantee best-effort cleanup in `finally`. For whole-file replacement use atomic same-volume rename where supported; document cross-filesystem and Windows sharing limitations.
- Return unambiguous written-byte counts, remote errors and retry/idempotency information. Audit device, tenant, operation and byte count, not content or secrets. Test malformed base64, empty payload, non-ASCII/binary round-trip, truncation, symlink escape, tenant denial, spool cleanup on failure, and interrupted uploads on Windows and Linux.
- A new MCP tool manifest and ChatGPT connector refresh are required before public binary acceptance. Do not advertise binary safety based on the existing text API.

## Acceptance

CI and security checks must pass for this branch. Before deployment, use a dedicated authorized Windows Temp fixture, back up existing content, verify rewrite -> append -> readback, and restore exact bytes. Do not merge or deploy on test failures.
