#!/usr/bin/env python3
"""Add a Driver0000 + DriverOrder entry to an OVMF variable store.

BDS loads Driver#### options before any Boot#### option, which is how the
MockOpalDxe test driver (test/edk2-mock-opal/) gets dispatched before the PBA.
Driver0000 uses a short-form file-path device path; EDK2 BDS expands it by
searching all SimpleFileSystem instances, so it finds the driver on the ESP
regardless of disk layout.

Note: under enforcing Secure Boot, BDS *silently* skips an unsigned/unknown
Driver#### image — the driver's serial marker is the only evidence it ran.

  add-driver-entry.py <in-vars.fd> <out-vars.fd> <efi-path e.g. \\EFI\\MOCK\\MOCKOPALDXE.EFI> [fault]

If [fault] is given (auth-fail | fail-mbrdone | fail-after-unlock), the
MockOpalFault variable (vendor GUID a8d866f2-64a0-11f1-a8dc-56433c165986,
NV+BS+RT) is additionally set to that ASCII value so MockOpalDxe arms the
corresponding fault at dispatch (see test/edk2-mock-opal/README.md).

Requires the virt-firmware Python package.
"""
import struct
import sys

from virt.firmware.efi import efivar, devpath, bootentry, ucs16
from virt.firmware.varstore import edk2

ATTR = (efivar.EFI_VARIABLE_NON_VOLATILE |
        efivar.EFI_VARIABLE_BOOTSERVICE_ACCESS |
        efivar.EFI_VARIABLE_RUNTIME_ACCESS)

MOCK_OPAL_FAULT_GUID = 'a8d866f2-64a0-11f1-a8dc-56433c165986'

if len(sys.argv) not in (4, 5):
    sys.exit(__doc__)
inp, outp, efipath = sys.argv[1], sys.argv[2], sys.argv[3]
fault = sys.argv[4] if len(sys.argv) == 5 else None

store = edk2.Edk2VarStore(inp)
varlist = store.get_varlist()

entry = bootentry.BootEntry(attr=bootentry.LOAD_OPTION_ACTIVE,
                            title=ucs16.from_string('MockOpalDxe'),
                            devicepath=devpath.DevicePath.filepath(efipath))

drv = efivar.EfiVar(ucs16.from_string('Driver0000'), attr=ATTR, data=bytes(entry))
varlist['Driver0000'] = drv

order = efivar.EfiVar(ucs16.from_string('DriverOrder'), attr=ATTR,
                      data=struct.pack('<H', 0))
varlist['DriverOrder'] = order

if fault is not None:
    varlist['MockOpalFault'] = efivar.EfiVar(ucs16.from_string('MockOpalFault'),
                                             guid=MOCK_OPAL_FAULT_GUID,
                                             attr=ATTR, data=fault.encode())

store.write_varstore(outp, varlist)
suffix = f', MockOpalFault={fault}' if fault is not None else ''
print(f'wrote {outp}: Driver0000 -> {efipath}, DriverOrder=[0000]{suffix}')
