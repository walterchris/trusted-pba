# Sourced helper: resolve a MATCHED OVMF firmware pair (CODE + VARS of the same
# build/size — mixing a 2M CODE with a 4M VARS does not boot). Prefers the
# secure-boot-capable CODE; its enforcement is inert in Setup Mode, so unsigned
# images still boot when paired with a stock (Setup Mode) VARS.
#
# Sets: OVMF_SECBOOT_CODE, OVMF_VARS_TEMPLATE (matched). Honors pre-set values.
_ovmf_pair() {
	local pairs=(
		"/usr/share/OVMF/OVMF_CODE.secboot.fd:/usr/share/OVMF/OVMF_VARS.fd"            # Fedora 2M
		"/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd:/usr/share/edk2/ovmf/OVMF_VARS.fd"
		"/usr/share/OVMF/OVMF_CODE_4M.secboot.fd:/usr/share/OVMF/OVMF_VARS_4M.fd"      # Ubuntu 4M
	)
	local p code vars
	for p in "${pairs[@]}"; do
		code="${p%%:*}"
		vars="${p##*:}"
		if [ -f "$code" ] && [ -f "$vars" ]; then
			: "${OVMF_SECBOOT_CODE:=$code}"
			: "${OVMF_VARS_TEMPLATE:=$vars}"
			return 0
		fi
	done
	echo "no matched secure-boot OVMF pair found; set OVMF_SECBOOT_CODE + OVMF_VARS_TEMPLATE" >&2
	return 1
}
_ovmf_pair
