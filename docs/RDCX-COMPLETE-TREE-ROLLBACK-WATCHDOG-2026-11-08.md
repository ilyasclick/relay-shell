# Complete-tree rollback watchdog

Status: isolated staging candidate, not production
Date: 2026-11-08
Base: `f0534a966d0e89fd56ae181113239922e74496e4`

## Covered invariants

- The live tree must exactly match the recorded candidate manifest.
- The backup tree must exactly match the stable baseline manifest.
- A process lock serializes the precondition check and tree swap.
- The backup is copied and rehashed before the live tree is moved.
- The complete candidate tree is quarantined instead of deleted.
- The replacement tree is atomically installed on the same filesystem.
- The replacement tree is rehashed and optionally passed to a postflight health check.
- An acceptance marker makes a later watchdog invocation a no-op.
- A concurrent edit, unexpected file, corrupted backup or failed precondition refuses rollback.

## Scope boundary

The implementation is a disposable-tree rehearsal. It does not install a
systemd unit, modify the production gateway, restart services, touch ACLs or
network rules, or provide an out-of-band recovery channel. Production rollout
remains blocked until this logic is independently rehearsed against the actual
staging runtime and a separate recovery path is available.
