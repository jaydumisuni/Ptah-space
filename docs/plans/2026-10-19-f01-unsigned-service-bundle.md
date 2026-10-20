# F01 deterministic unsigned service artifact candidate

Date: 2026-10-19. Status: engineering candidate, not F01 release or
production package signing.

Usage:
- Build Ptah Control and Node using a pinned, separately qualified source
  revision and toolchain, without changing host service state.
- Feed the existing binaries into build_f01_service_bundle.py, together
  with the exact source-commit reference.
- The tool writes a deterministic tar whose manifest inventories both
  binaries and their SHA-256 digests. The verify path rejects missing,
  extra, altered or noncanonical members and any claimed release/admission.
- No binary executes during packing or verification; no network, installer,
  service manager, signing key, E01 enrollment, E02 dispatch or Supervisor
  authority is introduced. Oracle remains machine transport; Ptah workspace.

The source commit reference is caller-supplied metadata, NOT an attestation
that binaries truly derive from that commit. Independent build provenance,
approved source, supply-chain/signer approval and reproducibility across two
builders remain separate gates. The archive is explicitly unsigned and
native_execution_admitted=false; publication and production F01 remain NO-GO.

Tests: 8 Python cases passed locally, including byte-identical repeated
archives, corrupt payload detection, forged release flag rejection, symlinks,
incomplete service sets, existing-output protection and no process execution.

Remaining F01 acceptance: independently reproducible builds at frozen heads,
signed package manifests with properly protected signing keys, validated
service dependency closure, Windows/Linux approved installation and
fail-closed startup/rollback on admitted hosts, independent review and owner
release decision. This feature does not satisfy F02-F07 acceptance.
