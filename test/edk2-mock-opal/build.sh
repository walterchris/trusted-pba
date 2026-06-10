#!/usr/bin/env bash
#
# Build MockOpalDxe.efi against a pinned upstream edk2 release.
#
# Approach: a minimal standalone package DSC in this directory, exposed to the
# edk2 build via PACKAGES_PATH. Chosen over patching a module into
# MdeModulePkg.dsc because nothing in the edk2 tree is ever modified — bumping
# EDK2_TAG below is the entire upgrade procedure (least maintenance). Only
# MdePkg library instances are consumed; MdeLibs.dsc.inc supplies the
# toolchain-coupled ones.
#
# The edk2 checkout, BaseTools binaries, and build intermediates live in a
# cache dir (TPBA_EDK2_CACHE, default ~/.cache/tpba-edk2) keyed by the tag, so
# re-runs only recompile the driver itself.
#
# Prerequisites: git, make, gcc/g++, nasm, iasl, libuuid headers, python3.
# Output: MockOpalDxe.efi in this directory.

set -euo pipefail

EDK2_TAG="edk2-stable202605"   # pinned upstream release (bump deliberately)
EDK2_REPO="https://github.com/tianocore/edk2.git"
TOOLCHAIN="GCC"
TARGET="RELEASE"

HERE="$(dirname "$(readlink -f "$0")")"
CACHE_DIR="${TPBA_EDK2_CACHE:-$HOME/.cache/tpba-edk2}"
EDK2_DIR="$CACHE_DIR/$EDK2_TAG"

# 1. Pinned edk2 checkout (cached). Only the submodules the build actually
#    touches are fetched (BaseTools' brotli; mipisyst, whose include dir
#    MdePkg.dec references) — CryptoPkg's openssl etc. are not.
if [ ! -e "$EDK2_DIR/edksetup.sh" ]; then
	mkdir -p "$CACHE_DIR"
	git clone --depth 1 --branch "$EDK2_TAG" "$EDK2_REPO" "$EDK2_DIR"
fi
git -C "$EDK2_DIR" submodule update --init --depth 1 \
	BaseTools/Source/C/BrotliCompress/brotli \
	MdePkg/Library/MipiSysTLib/mipisyst

# 2. BaseTools (cached by its own outputs).
if [ ! -x "$EDK2_DIR/BaseTools/Source/C/bin/GenFw" ]; then
	make -C "$EDK2_DIR/BaseTools" -j"$(nproc)"
fi

# 3. Drift guard: the checked-in Discovery0 header must match the golden
#    fixture (shared fake-Opal spec, test/fixtures/opal/).
"$HERE/gen-discovery-header.sh" --check

# 4. Build the driver. PACKAGES_PATH makes test/edk2-mock-opal visible as the
#    package directory "edk2-mock-opal" next to the edk2 packages.
export WORKSPACE="$EDK2_DIR"
export PACKAGES_PATH="$EDK2_DIR:$(readlink -f "$HERE/..")"
cd "$EDK2_DIR"
set +u
# shellcheck disable=SC1091
. ./edksetup.sh BaseTools >/dev/null
set -u
build -p edk2-mock-opal/MockOpalPkg.dsc -a X64 -t "$TOOLCHAIN" -b "$TARGET" \
	-n "$(nproc)"

cp "$EDK2_DIR/Build/MockOpalPkg/${TARGET}_${TOOLCHAIN}/X64/MockOpalDxe.efi" \
	"$HERE/MockOpalDxe.efi"
echo "built $HERE/MockOpalDxe.efi ($EDK2_TAG, $TARGET/$TOOLCHAIN)"
