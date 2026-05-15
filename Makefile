# +-------------------------------------------------------+
# | EBPF PROJECT MAKEFILE (FIXED)                         |
# +-------------------------------------------------------+

# CONFIGURATION
BINARY    = ebpf-interface
# Use "." to include all files in the current package
PACKAGE   = .
BPF_GEN   = ebpf_interface_bpfel.go ebpf_interface_bpfel.o
CONTROLLER_BIN = controller/controller
CONTROLLER_PKG = ./controller

# PHONY TARGETS
.PHONY: all generate build build-controller clean dist help run run-controller

# DEFAULT MODE
all: generate build

# STEP 1: GENERATE
generate:
	@echo "--- [STEP] Running go generate ---"
	go generate ./...

# STEP 2: BUILD
# Build generated BPF objects first, then binaries. Remove intermediate generated files after build.
build: generate
	@echo "--- [STEP] Compiling binary: $(BINARY) ---"
	go build -o $(BINARY) $(PACKAGE)

	@echo "--- [STEP] Compiling controller: $(CONTROLLER_BIN) ---"
	go build -o $(CONTROLLER_BIN) $(CONTROLLER_PKG)

	@echo "--- [STEP] Cleaning generated BPF artifacts ---"
	rm -f $(BPF_GEN)

# Build controller CLI (separate target so `make build-controller` rebuilds)
build-controller:
	@echo "--- [STEP] Compiling controller: $(CONTROLLER_BIN) ---"
	go build -o $(CONTROLLER_BIN) $(CONTROLLER_PKG)

# CLEAN-BUILD MODE (dist)
dist: generate build
	@echo "--- [STEP] Cleaning intermediate files ---"
	rm -f $(BPF_GEN)
	@echo "--- [DONE] Directory is clean, binary is ready ---"

# CLEANUP
clean:
	@echo "--- [STEP] Removing all artifacts ---"
	rm -f $(BINARY) $(BPF_GEN) $(CONTROLLER_BIN)

# Run the ebpf-interface binary (requires sudo for XDP attach)
run: build
	@echo "--- [STEP] Running $(BINARY) (requires sudo) ---"
	sudo ./$(BINARY) -iface upfgtp

# Build and run controller CLI
run-controller: build-controller
	@echo "--- [STEP] Running controller ---"
	./$(CONTROLLER_BIN)

# HELP
help:
	@echo "AVAILABLE COMMANDS:"
	@echo "  make        : Standard build (keeps generated files)"
	@echo "  make dist   : Clean build (deletes generated files after build)"
	@echo "  make clean  : Remove binary and all generated files"