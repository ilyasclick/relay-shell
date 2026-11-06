# Binary read-only API review (2026-11-06)

Status: NOT ACCEPTED. This isolated branch starts from `rdcx-gate-hardening`, not PR #5's obsolete Windows append base. PR #8 is still open and unmerged. Do not merge this branch as a substitute for implementation or tests.

PR #5 head reviewed: `52c7b2751bfff02173904ec628a8821e95e6d41e`. Binary writes are intentionally disabled; retain that fail-closed behavior.

Confirmed read defect: Windows `read_file_bytes` calls `FileStream.Read` only once for `max_bytes + 1`. A stream read may return fewer bytes than requested before EOF, producing a false `TRUNCATED=0` and an incomplete chunk. Replace with a bounded loop until requested bytes are filled or Read returns zero. Keep bounded response size and strict canonical Base64.

Additional review gates: verify zero-byte acknowledgement and EOF offset; exact chunk SHA-256 (not whole-file hash); reject malformed/noncanonical Base64, oversized output and denial markers; validate tenant/files grants before any backend call; ensure Windows shell and POSIX path handling fail closed; never return backend content in errors; test short reads and denied/error exits. No live fixtures or production changes were performed.

PR #7 is merged; PR #8 is not merged at review time. Do not migrate PR #5 onto PR #8 until its merge and current target SHA are verified. No unsafe write implementation should be enabled without separate security acceptance.
