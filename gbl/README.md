# GBL Compliance Requirement Test

Host-driven test that checks device properties when booted with GBL.

## Manual instructions (2025Q2)

Per 2025Q2 requirements, GBL is strongly recommended. To test device
compatibility with GBL:

1.  Reboot device to bootloader mode then flash the officially signed GBL image
    to the `efisp` partition.
2.  Reboot device to Android userspace. It is expected to be booted with GBL.
3.  Run the test `atest VtsGblHostTest`.
4.  (Optional) Restore device to its original bootloader.
    1.  Reboot to bootloader mode. Since we were booting with GBL, this should
        be the fastboot interface provided by GBL.
    2.  Erase the `efisp` partition with `fastboot erase efisp` then reboot.
    3.  Since GBL is wiped, device should be booted with its original bootloader
        (e.g. ABL) and GBL-specific properties should no longer be present.
