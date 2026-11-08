# Tier-3 identity-binding change

Status: isolated candidate, not production
Date: 2026-11-08
Base: rdcx-gate-hardening at f0534a966d0e89fd56ae181113239922e74496e4

## Decision

The Gateway calls one shared administrative relay and currently does not
propagate the originating OAuth principal into the relay challenge lifecycle.
Therefore authenticated Tier-3 is fail-closed unless the Gateway is in
explicit single-client mode and the persisted client-to-tenant mapping contains
exactly one client matching the active principal and tenant.

Both privileged entry points are covered:

- `exec_elevated`
- `confirm_elevated`

Confirmation also requires the exact positive relay acknowledgement
`[armed: re-issue the exact Tier-3 call now to execute it]`; errors and
non-positive responses are denied and audited as denial/error, never as success.

## Deliberate non-claims

This candidate does not establish multi-client binding, challenge provenance,
device/backend/argument binding, restart persistence, or live two-account
acceptance. It must not be merged or deployed as a complete Tier-3 solution.

## Acceptance gates

1. Run the isolated unit suite and full CI on the exact final commit.
2. Review the complete source tree and import path.
3. Add an independently verified broker/Gateway identity propagation design
   before enabling authenticated multi-client Tier-3.
4. Keep production unchanged until separate rollout authorization.
