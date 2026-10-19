# F03 bounded guest execution proof — development evidence

19 October 2026. Scope: independent Ptah virtualization substrate testing
before any Prime OS integration, not F03 or OS-ready acceptance.

## What is implemented
- Explicit opt-in x86/QEMU/KVM guest boot test: compiles a deterministic
  512-byte BIOS sector using local GNU as/ld.
- Guest code runs x86 instructions and writes the exact expected marker
  to a bounded QEMU debug port, then triggers explicit VM exit.
- The VM uses one vCPU, 128 MiB of RAM, a temporary disk, no networking,
  no display, no interactive monitor and a hard 3–20 second time budget.
- The original guest disk SHA-256 is checked after QEMU exits. Temporary
  assembler outputs and the boot disk are deleted. No host partitions or
  resident Ptah services are touched.
- The CLI is passive by default. A VM starts only with an explicit
  '--run' invocation. A successful test never claims OS guest boot,
  encrypted update, service isolation, production E01/E05 admission or
  owner/reviewer approval.
- Negative and conformance tests are run in pinned CI without starting a VM.

## Physical KRATOS evidence
- 19 Oct 2026: command 'python3 tools/f03_ephemeral_guest_boot.py --run'
  passed twice. Both runs recorded 'guest_boot_sector_executed: true',
  marker SHA-256
  0c2ae23cb2eae68b5e3fa0291a098e21326c44c165d3da7509c0c81ef3816604,
  'guest_disk_unchanged: true', and 'temporary_files_removed: true'.
- Combined 29 offline Python conformance tests passed, including explicit
  opt-in enforcement, missing tool/KVM refusal, and no guest release claims.
- A previous attempt to boot KRATOS's 7.0.0-38 Linux kernel was blocked by
  existing '/boot' file permissions (mode 0600). We did not escalate
  privileges or change permissions. This boot-sector proof avoids that
  condition but is NOT equivalent to Linux guest boot.

## Still open
F03 awaits a real isolated guest OS under a tested Provider, virtual disk
recovery after interruption, resource limit and starvation evidence, durable
Artifacts bound to a verified Workspace/Node, independent reviewer/owner
acceptance. Prime OS integration deliberately remains out of scope until
the standalone Ptah work is done.

Oracle is the authenticated machine transport; Ptah is the shared workspace.
Neither this test nor QEMU confers E01/E02/E05 native execution authority.
