# Ptah candidate workspace — Nodie U10S/WF7520 original OS prephysical boot

**Status: CANDIDATE / NOT AN A07 ADMISSION / NO DEVICE ACTIVITY AUTHORIZED**

This is the Ptah-side content-addressed source-world handoff for the TTG-Simulation Nodie full-OS work. The source remains the exact KRATOS `ZTE-unlock` recovery authority, not Ptah. Ptah contributes immutable source/coverage/provenance concepts (C01/C02/A07), not proof of firmware execution.

## Immutable observed inputs

Source workspace: `/home/kratos/projects/ZTE-unlock/home-mifi/.workspace/recovery/`.

- ImageFS `mtd4` candidate: 8,388,608 bytes; SHA-256 `8da81c1d5aff9175a50376250994fe876890d7c5dde71636392bcd1e9cb6ad4f`; **64/64 physical logical block readback matched** on 2026-10-11.
- rootfs candidate: 50,331,648 bytes; SHA-256 `4f2099617e9ef4a28c5ad9e6138a5b5c9cd9f9e2f62ab38447ccecddea12f3ab`. Local candidate only; **live installation not proved**.
- resource candidate: 8,388,608 bytes; SHA-256 `332c38d895ec921fcf5d9e3ce814a76359ace4d13eb15a9b3fb55ab4d8870587`. Local candidate only.
- userdata candidate: 25,165,824 bytes; SHA-256 `f3cfe8c40dd824c2dd74acebcec78e09bf06f492d8a5b8cf80581f339be8e5a8`. Local candidate only.
- parent AP `ap_cpuap.bin`: MD5 `ccb97ada4090b245e8e96268aa7a7ef0`. Frozen parent candidate identity.

**Protected/never-write:** zloader, uboot, uboot-mirr, nvrofs, yaffs, zterw. Device-specific NV/calibration is not reconstructed from a generic golden image.

## Coverage semantics

Known source byte identities and offline file-tree/init hooks: **verified locally**. Kernel, BootROM, PMIC, GICv3/EL3, CPU exceptions, M0, ZSP, NAND timing/ECC, charger/power-key and LCD peripherals: **unknown/incomplete** in the virtual model. Unknown must not be upgraded to Complete merely because image hashes match.

The existing Ptah C01/C02 evidence and A07 Object/Revision contracts can represent and verify source objects; none of those automatically executes the original device firmware. This candidate is not represented as an imported Ptah canonical Object, accepted Revision, admitted Node, qualified Workspace Movement or Recovery Verification.

## Paired TTG-Simulation result

Local KRATOS trial:
`/home/kratos/projects/TTG-Simulation/.tmp/nodie-full-os-20261011/`

- `nodie_boot_twin.py` + `verified-inputs.json` + `boot-model-result.json` produced **MODEL_PASS_ONLY**.
- 1 **hypothetical** normal-power boot path reaches *modeled* Booting -> Idle -> Browse/Recovery.
- 12 hostile/negative boot worlds halt correctly, including USB insertion charger-only, low voltage, missing PS-hold, stale downloader, image, kernel and display faults.
- TTG-Simulation G1 ranked the evidence-first candidate **77.5 structural points, 13/13 hostile worlds**, with `authority_granted=false`. This is NOT a real U10S CPU/kernel boot.

## Promotion gate (closed)

Do not touch the physical MiFi or run catchers/flashes while building the model. Require **original ARM32 kernel/userland execution** in an adequately faithful ZX297520v3/WF7520 SoC emulation, with USB-insert-vs-POWER, 64/64 NAND coverage, real `/etc/rc`, framebuffer and WPS Browse/Recovery, plus independent Patrol/SRG review. A generic QEMU ARM board or the behavioral state model is not sufficient.

Reference machine requirements: the zx297520v3 SoC has Cortex-A53 running ARM32, GICv3, Cortex-M0 startup controller and separate ZSP LTE DSP, per Linux kernel platform documentation.

No source bytes are copied to this Ptah branch. No Ptah runtime success is claimed.
