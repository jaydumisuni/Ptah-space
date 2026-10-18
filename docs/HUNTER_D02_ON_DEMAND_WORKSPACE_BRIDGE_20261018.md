# Ptah D02 — Native Hunter on-demand Workspace bridge

Date: 2026-10-18
Status: local KRATOS proof PASSED; independent release/owner enrollment pending

The bin target `ptah-hunter-workspace` composes **Ptah's existing** A06 WorkspaceStore and D02 HunterAdapter / WorkspaceReader against a real durable A03 SQLite ledger. One bounded JSON request causes one native operation and the binary exits. No new standing service, namespace authority, new scheduler or duplicate filesystem-based workspace manager.

The `provision` action is a local, operator-owned provisioning primitive; **not** a chat command. It requires canonical Ptah owner/authority/policy refs and persists an A06 Workspace. The `inspect` action requires an already-known canonical Workspace ref, denies a different owner and performs exact D02 retrieval and active lifecycle check after A06 authority check. Both report `e02LeaseIssued=false`, `executionDispatched=false`, `localPathMaterialized=false`. No E02 resource reservation, Lease, Fence, Ptah Node execution, CAS file mount or Ptah D02 grant is invented.

The Python Hunter adapter, in a separate Hunter branch, pins the native binary by SHA-256, verifies its ownership and permissions, checks an already-enrolled owner Workspace through native Ptah, and binds that exact Workspace identity to a PETE/AgentOps planning continuity alias. The operator must independently supply a valid TTG Auth owner-to-Ptah Principal mapping. Anonymous or unenrolled callers cannot provision or inspect through Hunter.

## Proof

At KRATOS, native D02 tests 2/2 pass, existing D02 acceptance 18/18 pass, strict Clippy (all/pedantic) passes and formatting passes. Hunter native integration and owner-formation tests 16/16 pass; full Hunter owner-tool regression passes. A retained local isolated-fixture proof, separate from production owner enrollment, is stored in `Ptah-space/.workspace/evidence/hunter-d02-on-demand-20261018/`, with receipt SHA256 `eb2c03c56863ab7c11ed0e802820aa05620b62f68d9391cc44b12406ed245f73`. The test opened a native canonical Ptah Workspace, reread it in another process, and rejected an unrelated Principal. It did not enroll the real user.

Next: independently review source, merge under Ptah policy, configure exact owner enrollment on KRATOS, qualify Ptah E02 authenticated placement/lease authority, test a real owner-session operation and Ptah/Eco second-use. Do not describe source proof as a permanent Ptah production daemon or as all-armour execution closure.
