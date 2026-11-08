"""Tests for complete-tree rollback refusal and recovery semantics."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import TestCase

from tools.rdcx_rollback_watchdog import (
    RollbackRefused,
    rollback_tree,
    tree_manifest,
)


class RollbackWatchdogTests(TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.live = self.root / "live"
        self.backup = self.root / "backup"
        self.marker = self.root / "accepted"
        self.lock = self.root / "rollback.lock"
        for tree in (self.live, self.backup):
            (tree / "integrations" / "rdcx_gateway").mkdir(parents=True)
            (tree / "gateway.py").write_text("stable\n", encoding="utf-8")
            (tree / "integrations" / "rdcx_gateway" / "binary_files.py").write_text(
                "stable helper\n", encoding="utf-8"
            )
        (self.live / "gateway.py").write_text("candidate\n", encoding="utf-8")
        (self.live / "integrations" / "rdcx_gateway" / "binary_files.py").write_text(
            "candidate helper\n", encoding="utf-8"
        )
        self.baseline = tree_manifest(self.backup)
        self.candidate = tree_manifest(self.live)

    def tearDown(self):
        self.tempdir.cleanup()

    def call_rollback(self, postflight=None):
        return rollback_tree(
            live_root=self.live,
            backup_root=self.backup,
            baseline_manifest=self.baseline,
            candidate_manifest=self.candidate,
            acceptance_marker=self.marker,
            lock_path=self.lock,
            postflight=postflight,
        )

    def test_restores_complete_tree_and_keeps_candidate_quarantined(self):
        self.assertEqual(
            self.call_rollback(postflight=lambda root: tree_manifest(root) == self.baseline),
            "restored",
        )
        self.assertEqual(tree_manifest(self.live), self.baseline)
        self.assertTrue(self.live.with_name("live.candidate").is_dir())

    def test_acceptance_marker_blocks_restore(self):
        self.marker.touch()
        self.assertEqual(self.call_rollback(), "accepted")
        self.assertEqual(tree_manifest(self.live), self.candidate)

    def test_concurrent_tree_change_is_refused(self):
        (self.live / "unexpected.txt").write_text("race\n", encoding="utf-8")
        with self.assertRaisesRegex(RollbackRefused, "differs from candidate"):
            self.call_rollback()
        self.assertTrue((self.live / "unexpected.txt").exists())

    def test_corrupt_backup_is_refused(self):
        (self.backup / "gateway.py").write_text("corrupt\n", encoding="utf-8")
        with self.assertRaisesRegex(RollbackRefused, "differs from stable"):
            self.call_rollback()
        self.assertEqual(tree_manifest(self.live), self.candidate)

    def test_failed_postflight_preserves_recovered_tree(self):
        with self.assertRaisesRegex(RollbackRefused, "postflight"):
            self.call_rollback(postflight=lambda root: False)
        self.assertEqual(tree_manifest(self.live), self.baseline)
