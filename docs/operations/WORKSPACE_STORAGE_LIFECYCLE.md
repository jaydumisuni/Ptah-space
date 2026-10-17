# THETECHGUY — Workspace storage lifecycle

Scope: every project, test, agent/chat, build, simulation and Ptah workspace. Canonical GitHub home: jaydumisuni/Ptah-space/docs/operations/WORKSPACE_STORAGE_LIFECYCLE.md. Version 2026-10-17.

## Hard rule

Preserve knowledge and reproducibility; remove only verified recreatable bulk. This is a default operations constraint for ChatGPT, Hunter, Ptah, Supervisor, Formula and authorized collaborators, NOT permission to overwrite their independent safety rules.

- PERMANENT: Git source/commits, small proof manifests, release/custody-critical logs, signed witness receipts, persistent runtime state, databases, device/firmware backups, user assets, certificates and secrets. Never auto-delete.
- AFTER EVERY TEST: store one small, discoverable summary (prefer under 32 KiB): exact Git SHA, test/command/result, machine and UTC time, authoritative evidence pointer, output checksums and cleanup classification. Cross-link it from a GitHub PR/issue or indexed evidence directory. Do not multiply large logs or duplicate binaries as documentation.
- DISPOSABLE: Rust target directories, CI caches and regenerable intermediates, Python bytecode and package caches; never confuse them with durable proof.
- QUALIFICATION: a disposable build cache may be marked for pruning ONLY after its project has a reviewed passing receipt, the exact Git checkout is clean/unchanged, no compiler job is active, and source/required evidence is preserved. Keep at least 48 hours after marking; otherwise retain.
- CLEANUP: clean only the exact qualified cache via scoped Cargo clean; never remove an entire worktree, unclassified directory, firmware, device state, logs required for custody, or credentials. Refuse symlinks, ambiguous paths, unproven qualification or ongoing builds.
- BUDGET: audit project cache size daily. Flag under 15% filesystem free, under 40 GiB available, or over 10 GiB Cargo builds for one project. Avoid duplicate heavy builds when near these limits.
- FUTURE TASKS: before launching substantial work, reuse existing qualified artifacts when practical; set an artifact retention plan. On completion write the receipt and qualify disposable caches. This applies regardless of which agent/chat created them.
- MULTI-HOST: ATHENA and KRATOS follow the same policy; Athena protected Node identity files must remain on supported NTFS state with approved ACLs. Do not install unqualified automatic deletion tasks.
- EVIDENCE: a checksum alone is not sufficient if a release requires independently retrievable physical witness data. Preserve the required custody copy; minimize only duplicate intermediates.

KRATOS guard (audits only by default):
python3 ~/.local/share/ttg-storage-hygiene/storage_guard.py audit --root ~/projects
python3 ~/.local/share/ttg-storage-hygiene/storage_guard.py mark --project PROJECT --receipt PROOF
python3 ~/.local/share/ttg-storage-hygiene/storage_guard.py prune --root ~/projects
Only explicit --apply can prune already-qualified caches after 48 hours.

Audits overwrite latest-audit.json in ~/.local/state/ttg-storage-guard rather than accumulating indefinite logs. No cache is auto-qualified. On ambiguity, RETAIN and flag.
