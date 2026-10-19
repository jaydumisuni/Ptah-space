# Ptah F01–F07 OS-foundation preflight — candidate only

Date: 2026-10-19. Status: SOURCE CANDIDATE, not F01, E07 or OS-ready acceptance.

## Architecture rule

Oracle remains the authenticated machine transport for ChatGPT, Hunter and
other authorized agents on KRATOS, ATHENA and other enrolled systems. Ptah is
the neutral shared workspace. Ptah does not replace Oracle and does not decide
or approve work for Supervisor, Hunter, Cookpit, Sergeant or the owner.
Native E01/E02/E05 enrollment and dispatch are optional production features,
not prerequisites for ordinary Oracle-backed workspace use.

## Candidate delivery

- Strictly bounded, versioned design-only service and target profile. Includes
  explicit manual admission boundaries for optional Ptah Control and Node.
- Machine-readable independent evidence requirements for F01 through F07.
- Fail-closed preflight that rejects noncanonical profiles, duplicated JSON
  keys, secret/command fields, fake host admissions, missing proof categories,
  premature service activation and forged release approvals.
- Read-only candidate evidence index with non-authorizing NO-GO result.
- Adversarial tests and SHA-pinned CI, no additional third-party dependencies.
- No Node installation, systemd changes, network listeners, host reconfiguration,
  physical device writes, certificate creation or production-route changes.

## Remaining positive acceptance work

- F01: proven signed packages, service dependency closure and fail-closed boot.
- F02: actual hardware evidence, tested device rules and capability evidence.
- F03: isolated QEMU/KVM/libvirt or equivalent workload and recovery proof.
- F04: reproducible bootable image, offline installation and recovery media.
- F05: rollback-safe updates, encrypted recovery and interrupted-update proof.
- F06: usable Human Workspace shell and compositor integration, offline access,
  accessibility and restart conformance.
- F07: independently reviewed, repeatable OS-ready acceptance with physical
  host recovery and explicit owner go/no-go.

Native E07 production acceptance remains separately tracked. Do not mistake
a successful Oracle workspace handoff, fixture or process SIGKILL proof for
native E01 enrollment, E02 dispatch or hard power-loss recovery.

## Candidate check

    PYTHONPATH=tools python3 -m unittest tools/test_check_os_foundation.py -q
    python3 tools/check_os_foundation.py --profile conformance/os-foundation/foundation-candidate.json --evidence conformance/os-foundation/evidence-index.json

Expected successful check: execution_authorized=false,
release_authorized=false, native_e07=NO_GO, os_foundation=NO_GO, with 21 required
future independent proof categories. A green check only verifies an honest
non-activating plan; it is not completion of any F phase.
