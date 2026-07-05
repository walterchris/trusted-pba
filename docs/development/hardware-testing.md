# Manual hardware testing (Advantech eval board, `lpba`)

How to run `trusted-pba` on the real lab board — provision an Opal SED with our PBA
in its shadow MBR, boot it, and capture the result. Adapted from the customer
FirmwareCI flow in **`9elements/lumentum-pba`** at
`.firmwareci/` (`duts/lpba-advantech-eval1/dut.yaml`,
`workflows/function-testset1/tests/provision-and-boot-swissbit0.yaml`), which is the
source of truth for the lab wiring and the drive credentials.

> **Scope.** This is a *manual* procedure for developer bring-up / debugging. The
> automated path is FirmwareCI (Phase 8 / #24). Real SED hardware is **not** required
> for normal development — see [`../test-tooling-plan.md`](../test-tooling-plan.md).

> **Credentials.** The drive password, PSID (erase credential) and TPM NV handle are
> **not** duplicated here — they are secrets. Read them from the access-controlled
> `lumentum-pba/.firmwareci/duts/lpba-advantech-eval1/dut.yaml` (`PASSWORD`, and the
> PSID used in the provisioning workflow). Never commit them to this repo.

## Lab topology

| Thing | Value | Notes |
|---|---|---|
| dutagent | `nicodemus.lab.9e.network:1024` | `newdutctl -s <agent> lpba …` (power/serial) |
| Device | `lpba` | commands: `power`, `power-system`, `serial` |
| Host (SSH) | `lpba-host.lab.9e.network` | `root` + key `~/.ssh/fwci`; the NixOS provisioning host |
| BMC | `lpba-bmc.lab.9e.network` | IPMI; driven **by the dutagent** (no separate creds needed) |
| PiKVM | `pikvm9.lab.9e.network` | web/API `admin:admin`; serves the NixOS **HostImage** as virtual CD-ROM |
| Target SED | Swissbit `nvme-SN2000MA480GI-…` → `nvme1n1` | Opal 2.0; 128 MB shadow MBR |

The board boots the **NixOS host** (`lumentum-pba-ci`) from the PiKVM-mounted HostImage
(virtual CD-ROM). Provisioning is driven over SSH to that host; the PBA boot happens
after the drive's shadow MBR is loaded and a one-shot boot entry points at it.

`newdutctl` basics (note: flag is `-s`, and zsh does not word-split unquoted vars — inline it):
```
newdutctl -s nicodemus.lab.9e.network:1024 lpba power [on|off|cycle|reset|status]
newdutctl -s nicodemus.lab.9e.network:1024 lpba lock 45m        # reserve
newdutctl -s nicodemus.lab.9e.network:1024 lpba serial -t 180s  # monitor
newdutctl -s nicodemus.lab.9e.network:1024 lpba serial -keep-escapes -t 10s -- send-raw $'\x1b[B'  # send keys, keep VT100
```

## 0. Prerequisites

- Board reserved: `newdutctl -s <agent> lpba lock 45m`.
- Host reachable: `ssh -i ~/.ssh/fwci root@lpba-host.lab.9e.network` (boot the NixOS
  HostImage first if it isn't up — see [Recovery](#recovery)). The host has
  `sedutil-cli`, `tpm2_*`, `efibootmgr`, `sgdisk`, `losetup`, `mkfs.vfat`.

## 1. Build the PBA for a real drive

The PBA reads its unlock PIN from the compiled-in policy, so it must match the drive
password. The `sedtest` build embeds `policy_sed.json` (`sed_unlock: required`,
`sed_pin: "correct horse"`); provision the drive with that same password (§3).

```
GOOS=tamago GOOSPKG=github.com/usbarmory/tamago GOARCH=amd64 ~/.tamago/go1.26.4/bin/go build \
  -tags linkcpuinit,linkramsize,linkramstart,linkprintk,sedtest -trimpath \
  -ldflags "-s -w -E cpuinit -T 268500992 -R 0x1000 -X 'main.Version=$(git rev-parse --short HEAD)-sedtest'" \
  -o bin/trusted-pba-sedtest ./cmd/pba
objcopy --strip-debug --output-target efi-app-x86_64 --subsystem=efi-app \
  --image-base 0x10000000 --stack=0x10000 bin/trusted-pba-sedtest bin/trusted-pba-sedtest.efi
printf '\x26\x02' | dd of=bin/trusted-pba-sedtest.efi bs=1 seek=150 count=2 conv=notrunc,fsync status=none
```

## 2. Package as a shadow-MBR image (GPT + ESP)

`sedutil-cli --loadPBAimage` writes a **full disk image** to the shadow MBR. The
firmware boots it via an `efibootmgr` entry pointing at partition 1's
`\EFI\BOOT\BOOTX64.EFI`, so the image needs a GPT with an ESP holding our PBA there.
Build it on the host (has `losetup`/`sgdisk`):

```
scp -i ~/.ssh/fwci bin/trusted-pba-sedtest.efi root@lpba-host.lab.9e.network:/tmp/trusted-pba.efi
ssh -i ~/.ssh/fwci root@lpba-host.lab.9e.network '
  IMG=/tmp/tpba-pba.img; truncate -s 64M "$IMG"
  sgdisk --clear --new=1:2048:0 --typecode=1:ef00 --change-name=1:ESP "$IMG"
  LOOP=$(losetup -Pf --show "$IMG")
  mkfs.vfat -F 32 -n TPBAPBA "${LOOP}p1"
  MNT=$(mktemp -d); mount "${LOOP}p1" "$MNT"
  mkdir -p "$MNT/EFI/BOOT"; cp /tmp/trusted-pba.efi "$MNT/EFI/BOOT/BOOTX64.EFI"
  sync; umount "$MNT"; rmdir "$MNT"; losetup -d "$LOOP"'
```
(64 MB fits the 128 MB shadow MBR; FAT32 needs ≥ ~33 MB.)

## 3. Provision the drive (DESTRUCTIVE — PSID-erases the test drive)

Run on the host. `PW` = the `sedtest` PIN `correct horse`; `PSID`/dev from the lab.
This is the `.firmwareci` sequence **minus** the TPM-NVRAM steps (those are the
lumentum PBA's read-once credential model; our PBA uses the compiled-in policy PIN).

```
DEV=$(realpath /dev/disk/by-id/nvme-SN2000MA480GI-…); PW="correct horse"; IMG=/tmp/tpba-pba.img
sedutil-cli --yesIreallywanttoERASEALLmydatausingthePSID <PSID> "$DEV"   # revert
sedutil-cli --initialsetup "$PW" "$DEV"                                  # claim
sedutil-cli --enablelockingrange 0 "$PW" "$DEV"
sedutil-cli --setmbrdone off "$PW" "$DEV"                                # shadow MBR active
sedutil-cli --loadPBAimage "$PW" "$IMG" "$DEV"                           # write our PBA
```
Expected end state: `LockingEnabled=Y, MBREnabled=Y, MBRDone=N`. With `MBRDone=N` the
host now sees the shadow MBR's GPT/ESP: verify with
`partprobe "$DEV"; lsblk "$DEV"` → `nvme1n1p1 vfat "EFI System"`, and
`mdir -i "${DEV}p1" ::/EFI/BOOT` → `BOOTX64.EFI`.

## 4. Boot entry + boot the PBA

Create the one-shot boot entry **after** `loadPBAimage` and while `MBRDone=N` (so
`efibootmgr` reads the shadow MBR's GPT), then reset and capture serial:

```
efibootmgr -c -b 1337 -d "$DEV" -p 1 -L "Trusted PBA (sedtest)" -l "\\EFI\\BOOT\\BOOTX64.EFI"
efibootmgr -n 1337        # BootNext (one-shot)
# from your workstation:
newdutctl -s <agent> lpba power reset
newdutctl -s <agent> lpba serial -t 240s        # capture the boot
```
Success marker: **`TRUSTED-PBA: sed unlock ok`** (ours; the lumentum PBA prints
`INFO: Drive unlocked successfully!`). After a successful unlock the shadow-MBR
partition disappears, so `1337` stops resolving and the board falls through to the
next `BootOrder` entry — that is how the board returns to the NixOS host on success.

## Recovery

If the PBA does **not** unlock (fails closed / halts), the drive stays locked, the
shadow MBR keeps presenting, and — because `efibootmgr -c` prepends `1337` to
`BootOrder` — every reset re-boots the PBA and halts. To break the loop:

1. `newdutctl -s <agent> lpba power reset`, then over serial send `ESC` at
   `Press <DEL> or <ESC> to enter setup` to enter the AMI (Aptio) setup:
   ```
   newdutctl -s <agent> lpba serial -t 75s -- expect "to enter setup" send-raw $'\x1b' send-raw $'\x1b'
   ```
2. Navigate to **Save & Exit → Boot Override → "UEFI: PiKVM CD-ROM Drive"** (the NixOS
   HostImage) and press Enter. The AMI menu is redirected to serial as VT100 — use
   `-keep-escapes` and render it to see the cursor (the **selected item is fg=37
   bright-white on white bg**; normal items are fg=34 blue; section headers fg=30):
   ```
   newdutctl -s <agent> lpba serial -keep-escapes -t 10s -- send-raw $'\x1b[B'   # Down; repeat + re-render to land on the target
   newdutctl -s <agent> lpba serial -t 5s -- send-raw $'\r'                       # Enter
   ```
   (Left arrow `$'\x1b[D'` from Main wraps to Save & Exit. A VT100 render helper —
   track `ESC[row;colH`, place chars, mark fg=37 — is in the session scratchpad notes.)
3. Wait for SSH, then clean up:
   ```
   efibootmgr -B -b 1337                                   # delete our entry (restores BootOrder)
   sedutil-cli --yesIreallywanttoERASEALLmydatausingthePSID <PSID> "$DEV"   # revert drive to clean
   rm -f /tmp/tpba-pba.img /tmp/trusted-pba.efi
   ```

## Teardown

```
newdutctl -s <agent> lpba power off
newdutctl -s <agent> lpba unlock          # release the reservation
```

## Known result (2026-07-05, `main` @ commit with A1)

The `sedtest` PBA **boots and runs on the board** (`TRUSTED-PBA: start` /
`version …-sedtest` / `secure-boot: off`), then fails closed:
`sed unlock failed: no locked Opal SED among 4 storage security device(s)`. It did
**not** chainload or fall through — correct fail-closed behavior. The Swissbit was
provisioned (`LockingEnabled=Y, MBREnabled=Y`), so the PBA's **UEFI Storage Security
Discovery** did not identify it as a locked Opal SED — the known real-hardware
Discovery/`ReceiveData` issue tracked in **#79 / #81** (the UEFI-native unlock fixes
were WIP on `feat/opal-session-setup-79`, not on `main`). This is not a regression
from A1 (behavior-neutral). Next: re-run once the HW-unlock work lands, and consider a
`power cycle` (cold) rather than `power reset` (warm) to guarantee the SED re-locks.
