#!/usr/bin/env bash
#
# Shared Secure Boot test helpers for the QEMU matrices. SOURCED, not executed
# (like ovmf-pair.sh). Single-sources throwaway-key generation, OVMF enrollment,
# virt-fw-vars resolution, and the scenario runner so secureboot-matrix.sh and
# mock-opal-matrix.sh cannot drift — e.g. one copy dropping --no-microsoft would
# silently change what the enforcing store trusts.
#
# TEST keys only: ephemeral, generated in the caller's workdir, never committed
# (baseline §13).

# resolve_vfv sets the global VFV to the virt-fw-vars binary, or exits 2 if it is
# not installed. Sets a global (rather than echoing via $(...)) so the exit
# propagates to the caller instead of dying in a command-substitution subshell.
resolve_vfv() {
	VFV="${VIRT_FW_VARS:-$HOME/.local/bin/virt-fw-vars}"
	command -v "$VFV" >/dev/null 2>&1 || VFV="virt-fw-vars"
	command -v "$VFV" >/dev/null 2>&1 || {
		echo "virt-fw-vars not found (set VIRT_FW_VARS or: pip install virt-firmware)" >&2
		exit 2
	}
}

# gen_test_keys <workdir> <cn-prefix> — throwaway PK/KEK/db RSA-2048 self-signed
# certs at <workdir>/{PK,KEK,db}.{key,crt}.
gen_test_keys() {
	local work="$1" cn="$2" role
	for role in PK KEK db; do
		openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
			-subj "/CN=$cn $role/" \
			-keyout "$work/$role.key" -out "$work/$role.crt" 2>/dev/null
	done
}

# enroll_keys <template> <out> <guid> <workdir> [dbx_sha256] — enroll the workdir's
# PK/KEK/db into a copy of the OVMF VARS template, enforcing. --no-microsoft: only
# our test keys are trusted (so an MS-signed image would NOT validate). If a
# dbx_sha256 (hex Authenticode digest) is given, it is added to dbx — so an image
# the db would otherwise trust is revoked by hash (dbx overrides db). Uses global VFV.
enroll_keys() {
	local template="$1" out="$2" guid="$3" work="$4" dbx_sha256="${5:-}"
	local dbx=()
	[ -n "$dbx_sha256" ] && dbx=(--add-dbx-hash "$guid" "$dbx_sha256")
	"$VFV" --input "$template" --output "$out" \
		--set-pk "$guid" "$work/PK.crt" \
		--add-kek "$guid" "$work/KEK.crt" \
		--add-db "$guid" "$work/db.crt" \
		"${dbx[@]}" \
		--no-microsoft --secure-boot >/dev/null
}

# scenario <title> <cmd...> — run a scenario, printing ok/FAILED and setting the
# caller's `fail` variable to 1 on failure.
scenario() {
	echo; echo "===== $1 ====="; shift
	if "$@"; then echo "----- ok"; else echo "----- FAILED"; fail=1; fi
}
