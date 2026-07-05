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

> **⚠️ Password hashing — the critical gotcha.** `sedutil-cli` **hashes the password
> by default** (PBKDF2, salted with the drive serial). Our `sedtest` PBA sends the
> **raw** policy PIN bytes, so a hash-provisioned drive rejects it with
> `StartSession … NOT_AUTHORIZED (0x01)`. Provision with **`-n`** (no-hash) on
> **every** password command so the stored credential is the raw PIN. (A PBA that must
> unlock a *hash*-provisioned drive — e.g. one set up by sedutil/lumentum tooling —
> needs the `sedutil-pbkdf2` derive stage, ADR-0011 §3; not yet implemented.)

```
DEV=$(realpath /dev/disk/by-id/nvme-SN2000MA480GI-…); PW="correct horse"; IMG=/tmp/tpba-pba.img
sedutil-cli    --yesIreallywanttoERASEALLmydatausingthePSID <PSID> "$DEV"  # revert
sedutil-cli -n --initialsetup "$PW" "$DEV"                                 # claim (raw PIN)
sedutil-cli -n --enablelockingrange 0 "$PW" "$DEV"
sedutil-cli -n --setmbrdone off "$PW" "$DEV"                               # shadow MBR active
sedutil-cli -n --loadPBAimage "$PW" "$IMG" "$DEV"                          # write our PBA
```
Expected end state: `LockingEnabled=Y, MBREnabled=Y, MBRDone=N`. With `MBRDone=N` the
host now sees the shadow MBR's GPT/ESP: verify with
`partprobe "$DEV"; lsblk "$DEV"` → `nvme1n1p1 vfat "EFI System"`, and
`mdir -i "${DEV}p1" ::/EFI/BOOT` → `BOOTX64.EFI`.

## 4. Boot entry + boot the PBA

Create the one-shot boot entry **after** `loadPBAimage` and while `MBRDone=N` (so
`efibootmgr` reads the shadow MBR's GPT). **Use one-shot `BootNext` only and keep the
entry OUT of `BootOrder`** — otherwise `efibootmgr -c` prepends it to `BootOrder`, and
a *failed* unlock leaves the drive locked so the entry keeps resolving and the board
halt-loops on the PBA. With `BootNext`-only, a failed boot just needs another
`power cycle` to return to the host (no firmware-menu recovery). `<orig-order>` is the
pre-existing `BootOrder` (e.g. `0001,0002,0000`, where `0001` = the PiKVM CD-ROM host).

```
efibootmgr -c -b 1337 -d "$DEV" -p 1 -L "Trusted PBA (sedtest)" -l "\\EFI\\BOOT\\BOOTX64.EFI"
efibootmgr -o <orig-order>    # restore BootOrder WITHOUT 1337
efibootmgr -n 1337            # BootNext (one-shot)
# from your workstation — COLD cycle (see below), not warm reset:
newdutctl -s <agent> lpba power cycle
newdutctl -s <agent> lpba serial -t 240s        # capture the boot
```

> **⚠️ Cold `power cycle`, not warm `power reset`.** A warm reset does **not** re-lock
> the SED — the drive comes up `Locked=N`, so `selectSED` finds "no locked Opal SED"
> and the PBA fails closed. A cold `power cycle` (power loss) re-locks the range
> (`Locked=Y`, `MBRDone=N`) so the PBA can discover and unlock it.

Success marker: **`TRUSTED-PBA: sed unlock ok`** (ours; the lumentum PBA prints
`INFO: Drive unlocked successfully!`). After unlock the PBA opens the ESP and
chainloads the policy target; on a freshly-provisioned drive with no OS staged that
last step reports `chainload failed: … not found` — expected, the unlock is what this
validates.

## Recovery

**If you used `BootNext`-only (above):** a failed/halted PBA boot is harmless — just
`newdutctl -s <agent> lpba power cycle` and the board boots `BootOrder` back to the
NixOS host. Then SSH in and clean up (below).

**If `1337` ended up first in `BootOrder`** (e.g. you skipped the `-o` step), the board
halt-loops on the PBA. Break it via the firmware menu over serial:

1. `power cycle`, then send `ESC` at `Press <DEL> or <ESC> to enter setup` to enter AMI
   (Aptio) setup — do it *after* setup finishes loading (`Entering Setup…` clears):
   ```
   newdutctl -s <agent> lpba serial -t 75s -- expect "to enter setup" send-raw $'\x1b' send-raw $'\x1b'
   ```
2. Navigate to **Save & Exit → Boot Override → "UEFI: PiKVM CD-ROM Drive"** and Enter.
   The menu is serial VT100 — use `-keep-escapes` and render the grid to track the
   cursor (**selected item = fg=37 bright-white**; normal fg=34 blue; headers fg=30).
   The tab order is Main·Advanced·Chipset·Server Mgmt·Security·Boot·Save & Exit — move
   with Right (`$'\x1b[C'`), and **verify after every key: serial keystroke delivery is
   lossy (~50–60%)**, so send one, re-render, repeat rather than a fixed count.
   ```
   newdutctl -s <agent> lpba serial -keep-escapes -t 10s -- send-raw $'\x1b[B'   # Down; re-render, repeat
   newdutctl -s <agent> lpba serial -t 5s -- send-raw $'\r'                       # Enter on the target
   ```

Clean up (on the host, after either recovery):
```
efibootmgr -b 1337 -B                                   # delete our entry
sedutil-cli --yesIreallywanttoERASEALLmydatausingthePSID <PSID> "$DEV"   # revert drive to clean
rm -f /tmp/tpba-pba.img /tmp/trusted-pba.efi
```

> **EFI NVRAM wedges under churn.** Repeated `efibootmgr -c`/`-B` can leave a corrupt
> `Boot####` entry ("Could not parse device path") and then fail new writes with
> `Could not prepare Boot variable: Input/output error`. A `power cycle` back to the
> host garbage-collects the store; the create then succeeds. Removing the efivars file
> directly does **not** help (firmware still holds the malformed NVRAM entry).

## Teardown

```
newdutctl -s <agent> lpba power off
newdutctl -s <agent> lpba unlock          # release the reservation
```

## Known result (2026-07-05, `main` @ A1)

**UEFI-native SED unlock works on real hardware** with the `sedtest` PBA:
```
TRUSTED-PBA: start / version …-sedtest / secure-boot: off
[hwdbg] dev 0/4: … Locked=false MBREnabled=false        (blank Opal drive)
[hwdbg] dev 1/4: … Locked=true  MBREnabled=true         (Swissbit — selected)
TRUSTED-PBA: sed unlock ok
TRUSTED-PBA: target "test-fixture" (EFI/TEST/TESTAPP.EFI) via firmware
TRUSTED-PBA: chainload failed: load "EFI/TEST/TESTAPP.EFI": not found   (expected: no OS on the erased drive)
```
(`[hwdbg]` lines require `-tags hwdebug`, PR #103.)

Getting here required fixing **two provisioning/procedure issues — not PBA code bugs:**
1. A **warm `power reset` doesn't re-lock the SED** → the drive was `Locked=N`, so
   `selectSED` reported `no locked Opal SED among 4`. A **cold `power cycle`** re-locks
   it. (This was the original mystery; it is a test-procedure fix.)
2. **`sedutil` hashes the password by default** → the raw-PIN PBA got
   `StartSession … NOT_AUTHORIZED (0x01)`. Provisioning with **`-n`** matches the raw PIN.

So `main`'s Opal unlock path is sound on hardware. Follow-ups: implement the
`sedutil-pbkdf2` derive stage (ADR-0011 §3) so the PBA can unlock hash-provisioned
drives without `-n`; and robust drive targeting by serial/WWN (#81). A truly
end-to-end cycle (unlock → chainload a real target) additionally needs an OS/testapp
staged on the drive's post-unlock partition.
