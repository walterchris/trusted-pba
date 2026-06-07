# Trusted PBA build (Phase 0).
#
# Requires the TamaGo toolchain (a Go fork). Install the tamago-go release and
# point TAMAGO at its `go` binary. The pinned version is go1.26.4 — keep it in
# lockstep with the github.com/usbarmory/tamago library version in go.mod.
#
#   TAMAGO=/path/to/tamago-go/bin/go make build
#
# Build flags (objcopy wrap, link tags, TEXT_START) follow the go-boot reference.

TAMAGO ?= /usr/local/tamago-go/bin/go
APP    := trusted-pba
BIN    := bin
SRC    := $(shell find . -name '*.go' -not -path './vendor/*')

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Image base 0x10000000; text starts 0x10000 above it (= 0x10010000).
IMAGE_BASE := 10000000
TEXT_START := $(shell echo $$((16#$(IMAGE_BASE) + 16#10000)))

BUILD_TAGS := linkcpuinit,linkramsize,linkramstart,linkprintk
LDFLAGS    := -s -w -E cpuinit -T $(TEXT_START) -R 0x1000 -X 'main.Version=$(VERSION)'
GOFLAGS    := -tags $(BUILD_TAGS) -trimpath -ldflags "$(LDFLAGS)"
GOENV      := GOOS=tamago GOOSPKG=github.com/usbarmory/tamago GOARCH=amd64

.PHONY: all build deps test qemu clean check_tamago

all: build

check_tamago:
	@test -x "$(TAMAGO)" || { echo "TamaGo not found at TAMAGO=$(TAMAGO). Install tamago-go and set TAMAGO."; exit 1; }

# Resolve and pin dependencies (go-boot + tamago) under the tamago target.
deps: check_tamago
	$(GOENV) $(TAMAGO) get github.com/usbarmory/go-boot@latest github.com/usbarmory/tamago@v1.26.4
	$(GOENV) $(TAMAGO) mod tidy

$(BIN):
	@mkdir -p $(BIN)

# ELF -> EFI application: objcopy into a PE/efi-app, then patch the PE
# Characteristics field at offset 150 (go-boot convention).
$(BIN)/$(APP).efi: $(SRC) go.mod | $(BIN) check_tamago
	$(GOENV) $(TAMAGO) build $(GOFLAGS) -o $(BIN)/$(APP) ./cmd/pba
	objcopy \
		--strip-debug \
		--output-target efi-app-x86_64 \
		--subsystem=efi-app \
		--image-base 0x$(IMAGE_BASE) \
		--stack=0x10000 \
		$(BIN)/$(APP) $(BIN)/$(APP).efi
	printf '\x26\x02' | dd of=$(BIN)/$(APP).efi bs=1 seek=150 count=2 conv=notrunc,fsync status=none
	@echo "built $(BIN)/$(APP).efi (version $(VERSION))"

build: $(BIN)/$(APP).efi

# Boot the built image in QEMU/OVMF and assert the Phase-0 serial markers.
qemu: build
	python3 test/qemu/expect-serial.py $(BIN)/$(APP).efi

# Host-side Go tests (Opal logic, policy, etc.) build for the host, not tamago.
test:
	go test ./...

clean:
	rm -rf $(BIN)
