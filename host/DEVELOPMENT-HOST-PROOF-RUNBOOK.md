# Phase 0C Development-Host Proof Runbook

## Purpose

This runbook produces a provider-neutral physical development-host qualification report for the first Ptah runtime implementation stage.

It deliberately does **not** require a particular operating-system distribution, kernel, guest operating system, virtual machine or container. Those are deployment/backend concerns unless a selected workload requires them.

A passing report proves only that the tested physical development host satisfies the portable mechanical baseline in `host/development-host-contract.json`.

It does **not** by itself:

- authorize Ptah runtime implementation;
- qualify a final deployment host;
- prove workload isolation or resource enforcement;
- accept a release;
- replace the later deployment/integration proof.

## Preconditions

Use a real physical development machine and an exact clean checkout of the selected Ptah proof-tool commit.

The external caller/control system is responsible for retaining its own invocation receipt. That receipt is reviewed separately from the Ptah report.

Do not place the physical proof output inside the repository checkout. The probe intentionally rejects that layout when `--expected-commit` is supplied because proof generation must not make the checkout dirty.

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

## 3. Run the physical probe

Provider-neutral form:

```text
python tools/run_development_host_probe.py \
  --repo-root . \
  --expected-commit <EXACT_PROOF_COMMIT> \
  --output ../ptah-development-host-evidence/development-host-report.json \
  --machine-label <LOCAL_LABEL> \
  --require-eligible
```

A private controller may additionally attach non-authoritative transport metadata:

```text
  --control-transport <TRANSPORT_CLASS> \
  --transport-receipt-id <EXTERNAL_RECEIPT_ID>
```

These values are caller-supplied metadata. The Ptah report does not validate the external transport receipt and cannot convert it into runtime authorization.

## 4. Required result

The command exits `0` only when `--require-eligible` is supplied and the report is eligible.

The report must contain:

```text
"record_type": "ptah.phase0c.development_host_probe"
"development_host_eligible": true
"runtime_implementation_authorized": false
"deployment_host_qualified": false
"release_accepted": false
```

The following arrays must be empty:

```text
capability_failures
observation_failures
repository_binding.failures
eligibility_failures
```

Every capability listed in `required_capabilities` must report `status: pass`.

The repository binding must show:

- exact expected commit before and after collection;
- a clean checkout before collection;
- a clean checkout after collection;
- no change of HEAD during collection.

## 5. Review the observations without turning them into predicates

The report records operating system, kernel/version, architecture, CPU count, total memory and free local storage.

These are evidence about the tested machine. They are **not** distribution or kernel acceptance locks for this development-host gate.

The portable acceptance checks are the mechanical capabilities defined by `host/development-host-contract.json`.

## 6. Preserve negative evidence

If the probe fails:

- retain the generated report if one exists;
- retain command output and exit status in the external evidence system;
- do not edit the report to make it pass;
- correct the machine/tooling condition or the approved contract, then run a new proof with a new receipt.

A retry does not erase the failed attempt.

## 7. Independent acceptance boundary

After a passing physical report exists, an independent reviewer must compare:

1. the exact tested Ptah commit;
2. the clean repository binding;
3. every required capability result;
4. required host observations;
5. the external invocation/control receipt;
6. retained failed/partial attempts, if any;
7. the applicable private authorization record.

Only the external authorization authority may decide whether the development-host gate is accepted and whether the next implementation phase is authorized.

## CI boundary

Repository CI runs the same portable probe on hosted Windows and Linux runners to prove cross-platform behavior and catch regressions.

Hosted CI is **diagnostic/regression evidence only**. It is not the required physical-host acceptance proof.
