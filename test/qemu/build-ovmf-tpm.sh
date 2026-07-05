#!/usr/bin/env bash
#
# Build a TPM-enabled, Secure-Boot-capable OVMF from the pinned edk2 tree — needed
# for measured-boot tests (ADR-0012 task 5). Fedora's edk2-ovmf package ships OVMF
# WITHOUT TPM2 support, so it exposes no EFI_TCG2_PROTOCOL and never measures the
# boot; this build (-D TPM2_ENABLE -D SECURE_BOOT_ENABLE) does.
#
# Reuses the same pinned edk2 checkout + cache as test/edk2-mock-opal/build.sh.
# Prints the built firmware paths (OVMF_CODE.fd / OVMF_VARS.fd) as KEY=VALUE on the
# last two lines so callers can eval them.
#
# Needs: git, gcc, make, python3, and the edk2 build deps (same as MockOpalDxe).
set -euo pipefail

EDK2_TAG="edk2-stable202605"   # keep in sync with test/edk2-mock-opal/build.sh
EDK2_COMMIT="b03a21a63e3bd001f52c527e5a57feddb53a690b"
EDK2_REPO="https://github.com/tianocore/edk2.git"
TOOLCHAIN="GCC"
TARGET="RELEASE"

CACHE_DIR="${TPBA_EDK2_CACHE:-$HOME/.cache/tpba-edk2}"
EDK2_DIR="$CACHE_DIR/$EDK2_TAG"
OUT_CODE="$EDK2_DIR/Build/OvmfX64/${TARGET}_${TOOLCHAIN}/FV/OVMF_CODE.fd"
OUT_VARS="$EDK2_DIR/Build/OvmfX64/${TARGET}_${TOOLCHAIN}/FV/OVMF_VARS.fd"

# Reuse an existing good build.
if [ -f "$OUT_CODE" ] && [ -f "$OUT_VARS" ] && [ "${TPBA_OVMF_FORCE:-}" != "1" ]; then
	echo "OVMF_TPM_CODE=$OUT_CODE"
	echo "OVMF_TPM_VARS=$OUT_VARS"
	exit 0
fi

# 1. Pinned edk2 checkout (cached), verified at the pinned commit.
if [ ! -e "$EDK2_DIR/edksetup.sh" ]; then
	mkdir -p "$CACHE_DIR"
	git clone --depth 1 --branch "$EDK2_TAG" "$EDK2_REPO" "$EDK2_DIR"
fi
EDK2_HEAD="$(git -C "$EDK2_DIR" rev-parse 'HEAD^{commit}')"
if [ "$EDK2_HEAD" != "$EDK2_COMMIT" ]; then
	echo "error: $EDK2_DIR is at $EDK2_HEAD, but $EDK2_TAG is pinned to $EDK2_COMMIT" >&2
	exit 1
fi

# 2. Submodules. OVMF with SB+TPM needs crypto (openssl) + decompress (brotli); the
#    full init (depth 1) is the robust superset and is a one-time cache cost.
git -C "$EDK2_DIR" submodule update --init --depth 1 >/dev/null

# 3. BaseTools (cached by its own outputs).
if [ ! -x "$EDK2_DIR/BaseTools/Source/C/bin/GenFw" ]; then
	make -C "$EDK2_DIR/BaseTools" -j"$(nproc)" >/dev/null
fi

# 4. Build OVMF X64 with Secure Boot + TPM 2.0.
export WORKSPACE="$EDK2_DIR" EDK_TOOLS_PATH="$EDK2_DIR/BaseTools" CONF_PATH="$EDK2_DIR/Conf"
cd "$EDK2_DIR"
set +u
# shellcheck disable=SC1091
. ./edksetup.sh BaseTools >/dev/null
set -u
build -p OvmfPkg/OvmfPkgX64.dsc -a X64 -t "$TOOLCHAIN" -b "$TARGET" -n "$(nproc)" \
	-D SECURE_BOOT_ENABLE=TRUE -D TPM2_ENABLE=TRUE -D TPM2_CONFIG_ENABLE=TRUE >/dev/null

[ -f "$OUT_CODE" ] && [ -f "$OUT_VARS" ] || { echo "error: OVMF build produced no firmware" >&2; exit 1; }
echo "OVMF_TPM_CODE=$OUT_CODE"
echo "OVMF_TPM_VARS=$OUT_VARS"
