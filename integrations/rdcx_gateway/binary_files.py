"""Bounded binary file transfer helpers for RDCX Gateway."""
from __future__ import annotations

import base64
import binascii
import hashlib
import re

CHUNK_LIMIT = 32768
OFFSET_LIMIT = (1 << 53) - 1
ENCODED_LIMIT = 4 * ((CHUNK_LIMIT + 2) // 3)


def validate_range(offset: int, max_bytes: int) -> None:
    if type(offset) is not int or not 0 <= offset <= OFFSET_LIMIT:
        raise ValueError("offset must be a nonnegative bounded integer")
    if type(max_bytes) is not int or not 1 <= max_bytes <= CHUNK_LIMIT:
        raise ValueError("max_bytes must be between 1 and 32768")


def decode_payload(content_base64: str) -> bytes:
    if not isinstance(content_base64, str) or len(content_base64) > ENCODED_LIMIT:
        raise ValueError("invalid base64 payload size")
    if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", content_base64):
        raise ValueError("invalid base64 alphabet")
    try:
        raw = base64.b64decode(content_base64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid base64 payload") from exc
    if len(raw) > CHUNK_LIMIT or base64.b64encode(raw).decode("ascii") != content_base64:
        raise ValueError("noncanonical or oversized base64 payload")
    return raw


def parse_read_response(output: str, max_bytes: int) -> dict:
    if len(output) > 65536:
        raise RuntimeError("backend output exceeded limit")
    # Keep the leading empty line for a valid zero-byte Base64 payload.
    lines = output.rstrip("\r\n").splitlines()
    if len(lines) != 2 or lines[1] not in ("TRUNCATED=0", "TRUNCATED=1"):
        raise RuntimeError("invalid backend binary read acknowledgement")
    raw = decode_payload(lines[0])
    if len(raw) > max_bytes:
        raise RuntimeError("backend returned more bytes than requested")
    return {
        "content_base64": lines[0],
        "bytes_read": len(raw),
        "content_sha256": hashlib.sha256(raw).hexdigest(),
        "truncated": lines[1] == "TRUNCATED=1",
    }
