# E06-03 reconnect comparison: no implicit authority

Date: 2026-10-19. Status: candidate for independent review; E06 remains unreleased.

Ptah is a neutral shared workspace; Oracle provides machine transport. Neither
Oracle connectivity nor a caller-supplied reconnect observation supplies native
E01, E02, E03, E04, E05 authority.

The E06 reconnect module:
- matches the exact queued IntentId, origin NodeId and sequence, Workspace,
  Activity, Operation, Attempt and canonical input digest;
- reports missing session, fence, transfer, checkpoint or host-profile evidence
  distinctly, and treats uncertain existing effects as unknown outcome;
- always requires external owner verification, even when fields appear present;
- does not dispatch, clear revalidation, issue a Lease, or persist any result
  from untrusted input;
- fails closed for unknown identities or existing immutable owner findings;
- leaves negative evidence persistence solely with the existing separately
  owner-controlled reconciliation receipt route.

Security review: initial candidate would have allowed an untrusted negative
observation to insert a permanent conflict. Removed that write path before
submission. Adversarial test proves an untrusted mismatch cannot poison queue
state, while genuine owner-controlled findings remain retained.

KRATOS offline qualification: cargo test -p ptah-offline-intent --locked --offline
PASS (8 new reconnect cases); strict package Clippy PASS; formatting PASS.
Reuse existing build target without new host services.

Not qualified: cryptographic verification of actual E01/Node sessions, current
E02 Fence/Lease, E03 Object lineage, E04 restore, E05 real host evidence,
A05 effects or owner approval. No true authenticated reconnect, live replay or
E06-07 release accepted. Those must come through external authoritative owners
and independent proof. E07 native release remains optional and separate.
