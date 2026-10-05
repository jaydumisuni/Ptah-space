# MTK Simulation Handoff

Updated: 2026-10-05

## Frozen authority

Sleeper branch:

`feature/mtk-meta-read-info-20261004`

Frozen capability/backend map commit:

`f91a26ac9bac9233d86189736cf49d116cc09129`

Do not replace the proven MTK META reader. Improvements extend it or replace it
only after a stronger backend is independently proven end-to-end.

## Ptah simulation branch

`feature/mtk-device-simulation-20261005`

The simulation lives under:

`simulations/mediatek/`

It is intentionally outside frozen C05/C08 physical mutation authority.

## Current state

### Physical-proven

- Preloader BootMode -> kernel META with observed `0E8D:2007`.
- Existing META MetaCore attach.
- MT6768 TargetVerInfo.
- ChipID.
- device-derived APDB acquisition.
- PRODUCT_INFO read.
- Barcode.
- IMEI inventory.
- BT/Wi-Fi MAC inventory.

### Donor-mapped, physical proof still required in Sleeper

- Preloader/DA partition lane.
- partition list.
- partition read.
- partition write.
- partition erase.

Authority recovered from Phoenix Partition Manager -> mtkclient-class
Preloader/DA backend.

### Blocked pending exact backend mapping/proof

- Serial/PSN.
- exit META/reboot normal.
- factory reset.
- FRP erase.
- IMEI/NVRAM write.
- bootloader unlock/relock.
- Android/ADB reboot-to-META.

## Simulation acceptance

The simulator must continue to prove:

- no command acknowledgement counts as state proof;
- META entry requires observed PID2007;
- partition operations require DA mode;
- write/erase require matching pre-backup and post-readback;
- mutation rollback is independently verified;
- simulated-only capabilities remain non-promotable;
- blocked capabilities remain blocked until donor mapping is frozen.

## Next action

Recover **Serial/PSN** first.

Use AndroidUtility.v200 + the already-proven device-derived APDB/PRODUCT_INFO
path. The schema evidence names `ADBSeriaNo`, but Sleeper must not expose a
Serial value until the nested field location or an equivalent read primitive is
independently proved.

After Serial/PSN is frozen, map **exit META/reboot normal** without changing the
proven read engine.

## Donor investigation rule

For every missing capability recover:

`button -> worker -> local API/protocol -> required device mode -> returned or
mutated state -> independent verification`

Do not add a donor-derived implementation merely because the donor UI exposes a
button.
