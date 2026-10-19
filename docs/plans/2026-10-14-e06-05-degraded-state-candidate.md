# E06-05 non-authoritative degraded status candidate

Date: 2026-10-14. Status: ENGINEERING CANDIDATE, not E06 or E07 acceptance.

`ptah_offline_intent::degraded::DegradedProjection` now reports:
- `offline_local`: durable local store empty;
- `queued_not_authorized`: local intents exist and require revalidation;
- `revalidating`: local owner check requested, no authority yet;
- `conflict`: unresolved inconsistency requiring owner disposition.

All projections preserve `authority_granted=false` and
`revalidate_required=true`; this module **cannot** produce
`online_authoritative`. Only a separate accepted E01-E05 owner path may
project that state after actual authenticated checks.

The `ptah-local-queue status` executable consumes this projection
rather than duplicating state logic. E06 package tests and strict
Clippy pass on KRATOS. No authenticated reconnect, remote permission
approval, execution, or production service is implied.
