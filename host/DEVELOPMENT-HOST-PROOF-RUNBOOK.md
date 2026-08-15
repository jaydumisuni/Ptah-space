# Phase 0C Development-Host Proof Runbook

## Purpose

This runbook produces a provider-neutral portable capability report used as one part of physical development-host qualification for the first Ptah runtime implementation stage.

It deliberately does **not** require a particular operating-system distribution, kernel, guest operating system, virtual machine or container. Those are deployment/backend concerns unless a selected workload requires them.

A passing Ptah report proves that the machine on which it executed satisfies the portable mechanical baseline in `host/development-host-contract.json` and that the tested repository checkout remained clean and exact.

The public probe cannot establish which external physical machine or control transport produced the report. Those identities come from independently reviewed external execution evidence that is retained separately.

A passing report therefore does **not** by itself:

- accept a physical development host;
- authorize Ptah runtime implementation;
- qualify a final deployment host;
- prove workload isolation or resource enforcement;
- accept a release;
- replace the later deployment/integration proof.

## Preconditions for an acceptance candidate run

Use the externally selected real physical development machine and an exact clean checkout of the selected Ptah proof-tool commit.

The external caller/control system is responsible for retaining an invocation receipt that establishes which physical machine executed the probe and how that execution was controlled. Do not encode those private identities into the public Ptah report.

Do not place the acceptance-candidate output inside the repository checkout. The probe intentionally rejects that layout when `--expected-commit` is supplied because proof generation must not make the checkout dirty.

## 1. Recover the exact candidate

```text
git clone https://github.com/jaydumisuni/Ptah-space.git
cd Ptah-space
git checkout <EXACT_PROOF_COMMIT>
git status --porcelain=v1
```

The final command must produce no output.

Record the exact commit:

```text
git rev-parse HEAD
```

It must equal `<EXACT_PROOF_COMMIT>`.

## 2. Choose an evidence path outside the checkout

Examples:

POSIX:

```text
mkdir -p ../ptah-development-host-evidence
```

PowerShell:

```text
New-Item -ItemType Directory -Force ..\ptah-development-host-evidence
```

Any equivalent external path is acceptable as long as it is not inside the repository worktree.

## 3. Run the portable capability probe

```text
python tools/run_development_host_probe.py \
  --repo-root . \
  --expected-commit <EXACT_PROOF_COMMIT> \
  --output ../ptah-development-host-evidence/development-host-report.json \
  --require-portable-pass
```

The public probe accepts no machine-name, controller-name, transport-name or external-receipt arguments. That separation is intentional.

## 4. Required portable result

The command exits `0` with `--require-portable-pass` only when every portable capability, required observation and repository-binding condition passes.

The report must contain:

```text
"record_type": "ptah.phase0c.development_host_probe"
"portable_capabilities_passed": true
"physical_host_identity_verified": false
"development_host_accepted": false
"runtime_implementation_authorized": false
"deployment_host_qualified": false
"release_accepted": false
```

The following arrays must be empty:

```text
capability_failures
observation_failures
repository_binding.failures
probe_failures
```

Every capability listed in `required_capabilities` must report `status: pass`.

The repository binding must show:

- exact expected commit before and after collection;
- a clean checkout before collection;
- a clean checkout after collection;
- no change of HEAD during collection.

The report must not contain external machine identity, external transport identity, or absolute/local filesystem paths from the executing machine. `repository_binding.repo_root` must be the provider-neutral value `.`; physical machine and local path binding remain in the separately retained private execution receipt.

## 5. Review the observations without turning them into OS predicates

The report records operating system, kernel/version, architecture, CPU count, total memory and free local storage.

These are evidence about the executing machine. They are **not** distribution or kernel acceptance locks for this development-host gate.

The portable checks are the mechanical capabilities defined by `host/development-host-contract.json`.

## 6. Establish physical-machine identity externally

The public probe deliberately refuses to claim physical-host or controller identity.

For a physical acceptance candidate, the external evidence system must retain a receipt that binds the invocation to the selected physical machine, the exact Ptah commit and the exact probe run. The independent reviewer validates that external receipt against the Ptah report.

A hosted CI runner may produce `portable_capabilities_passed: true`. That is expected and useful regression evidence, but it cannot become the physical development-host acceptance proof.

## 7. Preserve negative evidence

If the probe fails:

- retain the generated report if one exists;
- retain command output and exit status in the external evidence system;
- do not edit the report to make it pass;
- correct the machine/tooling condition or the approved contract, then run a new proof with a new external receipt.

A retry does not erase the failed attempt.

## 8. Independent acceptance boundary

After a passing report exists on the selected physical machine, an independent reviewer must compare:

1. the exact tested Ptah commit;
2. the clean repository binding;
3. every required capability result;
4. required host observations;
5. the separately retained external execution receipt proving the selected physical machine and control path;
6. retained failed/partial attempts, if any;
7. the applicable external authorization record.

Only the external authorization authority may accept the development-host gate and authorize the next implementation phase.

## CI boundary

Repository CI runs the same portable probe on hosted Windows and Linux runners to prove cross-platform behavior and catch regressions.

Hosted CI is **diagnostic/regression evidence only**. It may prove the portable checks, but it cannot prove or accept the selected physical development host.
