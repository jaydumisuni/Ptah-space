# THETECHGUY — permanent workspace storage and evidence rule

Applies to ALL projects and future ChatGPT, Hunter, Ptah, Supervisor, Formula, testing and build work under this directory.

1. Keep source, Git history, user files, runtime state, private credentials, device backups, and all signed/custody-critical recovery evidence. Do not auto-delete or move these.
2. Every significant test must leave a small discoverable receipt (host/date, exact commit or version, commands/results, hashes, proof references and cleanup class) linked from GitHub PR/issue or an evidence index. Do NOT preserve multi-GB build directories just to remember a test.
3. Cargo target, CI build outputs and other derived caches are disposable ONLY AFTER passing evidence is retained, the exact checkout is finalized, the build is inactive and its identity is verified. Keep a minimum 48 hours after qualification.
4. Before expensive work, check storage budgets and reuse qualified outputs if possible. After completing the task, classify/dispose of regenerable outputs with the guarded tool. Never blindly delete a worktree or unclassified files.
5. Future chats/projects MUST look up the canonical policy: https://github.com/jaydumisuni/Ptah-space/blob/governance/storage-lifecycle-20261017/docs/operations/WORKSPACE_STORAGE_LIFECYCLE.md
6. Ptah supplies workspaces; each client and reviewer retains its own approval authority. The storage rule grants no runtime release or deletion powers.
