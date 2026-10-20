# F02 USB device evidence and safe Prime OS rule handoff

Date: 19 October 2026. Status: engineering candidate, not F02 host
admission, device-policy activation or OS integration.

This tool inventories Linux USB vendor/product classes through sysfs without
reading serial numbers, device node contents, persistent user identifiers or
opening a USB transport. Duplicate classes are counted. Physical paths and
serials are never emitted. The inventory does not prove Ptah-native E01/E05
enrollment or hardware safety.

An optional rule profile must be design-only with explicit 4-digit lowercase
vendor/product IDs and a fixed restrictive group and mode. All output lines
are comments, NOT deployable active udev rules. Wildcards, duplicated IDs,
extra fields, device-open commands, permission 0666, enabled=true and
privileged groups are rejected.

Local KRATOS verification: read-only sysfs scan detected five valid USB
vendor/product classes; no serials or physical paths were retained.
Eleven positive and adversarial Python cases pass. No system file,
udev installation, group membership, USB device, physical host or service
was changed.

To inspect: python3 tools/f02_usb_inventory_rules.py --inventory

To inspect inactive draft: python3 tools/f02_usb_inventory_rules.py
--rules conformance/os-foundation/f02-empty-draft.json

Prime OS device integration later owns group existence, udev installation,
per-device signed admission, least-privilege access and rollback. This tool
does not address arbitrary PCI, GPU, MTP, serial, DIAG or firmware hardware
profiles, and does not complete full F02 acceptance. Oracle transport and
Ptah workspace remain separate; F01/F03 are separate milestones.
