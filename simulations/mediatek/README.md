# MTK Device Simulation — Ptah candidate

Status: candidate simulation only. This directory does not expand frozen C05/C08
physical authority.

## Purpose

Model one realistic MediaTek device through the service modes and capability
boundaries Sleeper must understand before TechGuy tools expose a function.

The model deliberately separates:

- **Simulation semantics** — what the device state should become when a candidate
  backend performs an operation correctly.
- **Donor mapping** — which donor button/worker/API/protocol teaches the backend.
- **Physical qualification** — what Sleeper has actually proved on hardware.
- **Product exposure** — what TechGuy-IMEI may safely show as available.

A successful simulation never upgrades a capability to physical proof.

## Current physical baseline

The accepted Sleeper MTK baseline is the MT6768 META work documented at
Sleeper commit `f91a26ac9bac9233d86189736cf49d116cc09129`.

Physically proven and frozen:

- Preloader BootMode acquisition requires actual re-enumeration to `0E8D:2007`.
- Existing META attach through MetaCore.
- TargetVerInfo and ChipID.
- Device-derived APDB discovery/receive.
- `AP_CFG_REEB_PRODUCT_INFO_LID` read.
- Barcode.
- IMEI inventory.
- Bluetooth/Wi-Fi MAC inventory.

Not yet physically qualified:

- Serial/PSN.
- exit/reboot-normal control.
- factory reset.
- FRP erase.
- partition list/read/write/erase in Sleeper.
- IMEI/NV mutation.
- bootloader unlock/relock.
- Android/ADB reboot-to-META.

## Backend routing law

The simulator uses the same routing law as the frozen Sleeper documentation:

| Capability family | Candidate authority |
|---|---|
| META inventory/APDB/NVRAM services | MetaCore |
| Preloader -> META | Sleeper MTK BootMode provider |
| Partition table/raw partition I/O | Preloader/DA, mtkclient-class backend |
| Bootloader security-state operations | Fastboot/bootloader-specific backend once mapped |

META is not treated as a universal transport.

## Donor roles

- **AndroidUtility.v200** — primary evidence for MetaCore/APDB/PRODUCT_INFO and
  related META service functions.
- **Phoenix** — primary evidence for Partition Manager and Preloader/DA
  mtkclient routing.
- **FenixToolPro** — candidate donor for remaining control/security functions;
  button labels are not accepted as backend proof.

A donor teaches Sleeper. Production tools never call donors directly.

## Mutation proof law

Simulation exercises mutations only when it can prove the mechanical contract:

1. exact target;
2. pre-operation backup;
3. backup hash;
4. operation;
5. post-operation readback/state observation;
6. post-operation hash/state match;
7. rollback;
8. rollback hash/state proof.

Physical promotion additionally requires a real hardware receipt from the exact
Sleeper backend. Simulation receipts alone are insufficient.

## Running

From the repository root:

```bash
python -m unittest discover -s simulations/mediatek -p 'test_*.py' -v
```

The acceptance suite intentionally includes blocked capabilities. A blocked
capability passing its *block* test is correct until donor/backend evidence
changes its qualification.

## Working order

1. Serial/PSN.
2. Exit META / reboot normal.
3. Factory reset backend mapping.
4. FRP erase backend mapping.
5. Partition list/read.
6. Partition write/erase with backup/readback/rollback.
7. IMEI/NVRAM write.
8. Bootloader unlock/relock last.

Update `HANDOFF.md` and `progress.json` after every promoted donor mapping or
physical proof.
