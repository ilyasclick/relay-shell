"""Fail-closed rollback rehearsal for a complete release tree."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import shutil
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Final

_MANIFEST_ENCODING: Final[str] = "utf-8"


class RollbackRefused(RuntimeError):
    """Raised when the observed tree is not the expected release state."""


def tree_manifest(root: Path) -> dict[str, str]:
    """Return SHA-256 values for every regular file in a release tree."""
    if not root.is_dir():
        raise RollbackRefused(f"release tree is not a directory: {root}")
    manifest: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RollbackRefused(f"symlink is not allowed in release tree: {path}")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            manifest[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return manifest


def manifest_digest(manifest: dict[str, str]) -> str:
    """Return a stable digest for a complete release-tree manifest."""
    payload = json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        _MANIFEST_ENCODING
    )
    return hashlib.sha256(payload).hexdigest()


@contextlib.contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def rollback_tree(
    *,
    live_root: Path,
    backup_root: Path,
    baseline_manifest: dict[str, str],
    candidate_manifest: dict[str, str],
    acceptance_marker: Path,
    lock_path: Path,
    postflight: Callable[[Path], bool] | None = None,
) -> str:
    """Restore a complete candidate tree only when every precondition matches."""
    if acceptance_marker.exists():
        return "accepted"

    with _exclusive_lock(lock_path):
        if acceptance_marker.exists():
            return "accepted"
        if tree_manifest(live_root) != candidate_manifest:
            raise RollbackRefused("live tree differs from candidate baseline")
        if tree_manifest(backup_root) != baseline_manifest:
            raise RollbackRefused("backup tree differs from stable baseline")
        if live_root.parent != backup_root.parent:
            raise RollbackRefused("live and backup trees must share a filesystem")

        quarantine = live_root.with_name(live_root.name + ".candidate")
        if quarantine.exists():
            raise RollbackRefused("candidate quarantine already exists")

        staging_parent = Path(
            tempfile.mkdtemp(prefix=live_root.name + ".rollback-", dir=live_root.parent)
        )
        staged = staging_parent / live_root.name
        moved = False
        try:
            shutil.copytree(backup_root, staged, symlinks=False)
            if tree_manifest(staged) != baseline_manifest:
                raise RollbackRefused("staged backup failed hash verification")
            live_root.replace(quarantine)
            moved = True
            staged.replace(live_root)
            if tree_manifest(live_root) != baseline_manifest:
                raise RollbackRefused("post-rollback tree failed hash verification")
            if postflight is not None and not postflight(live_root):
                raise RollbackRefused("postflight health check failed")
            return "restored"
        except Exception:
            if moved and not live_root.exists() and quarantine.exists():
                quarantine.replace(live_root)
            raise
        finally:
            shutil.rmtree(staging_parent, ignore_errors=True)
