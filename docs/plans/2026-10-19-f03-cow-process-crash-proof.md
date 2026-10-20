# F03 disposable copy-on-write guest crash and recovery proof

19 October 2026. Candidate only. No Prime OS changes.

The script tools/f03_cow_crash_recovery.py is PASSIVE by default.
Explicit --run uses local GNU assembler, linker, qemu-img and KVM to boot a
synthetic 512-byte BIOS test workload on a 1 MiB disposable backing disk.
The guest attempts one sector write to its COW overlay, emits a debugport
marker and halts. The runner then injects SIGKILL into the QEMU child only.
It reads the crashed overlay if possible WITHOUT trusting the guest
acknowledgment, discards it, recreates a clean overlay against the hashed
unchanged base, compares an entire projected disk byte-for-byte with the
baseline, and boots a second disposable guest through the same route.

It does not:
- kill or restart KRATOS or ATHENA, interrupt actual host power, or open
  physical disks;
- access live Ptah Node or Control production service, installer,
  service manager, certificate, user-owned VM, or Prime OS component;
- trust or replay a previously acknowledged-but-uncertain guest write;
- grant E01/E02/E05 authority, OS readiness, production admission or any
  reviewer/owner approval.

KRATOS actual evidence: two independent full script passes.
Both first and second guests acknowledged the test-sector write and both
created child QEMU processes were SIGKILLed. The first crash left its
write absent or incomplete despite a successful guest acknowledgment.
The raw base remained byte-identical (SHA256:
78f81bdf1d48b77e03daa128879a440ba3e8e4df6bce4152a1c13a0a12997cc8).
The recreated overlay projected exactly the 1 MiB baseline, and a new guest
boot succeeded from it. No network, 1 vCPU, 128 MiB RAM, temporary files
removed at exit. 41 combined local conformance tests PASS.

This proves controlled VM process interruption and baseline rollback, NOT:
durability of guest writes, crash-consistent filesystem recovery, boot of a
real guest operating system, VM resource starvation defense, malicious
input isolation, a physical power cut, native Ptah production enrollment,
full F03 qualification or an independent reviewer/owner approval.

Prime OS boot/install/update/rollback/compositor integration is LAST.
Oracle is the authorized host transport; Ptah is the shared workspace.
