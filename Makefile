# +-------------------------------------------------------+
# | EBPF PROJECT MAKEFILE (FIXED)                         |
# +-------------------------------------------------------+

# CONFIGURATION
BINARY    = ebpf-interface
# Use "." to include all files in the current package
PACKAGE   = .
BPF_GEN   = ebpf_interface_bpfel.go ebpf_interface_bpfel.o

# PHONY TARGETS
.PHONY: all generate build clean dist help

# DEFAULT MODE
all: generate build

# STEP 1: GENERATE
generate:
	@echo "--- [STEP] Running go generate ---"
	go generate ./...

# STEP 2: BUILD
# Changed $(GO_FILES) to $(PACKAGE) to fix "undefined" errors
build:
	@echo "--- [STEP] Compiling binary: $(BINARY) ---"
	go build -o $(BINARY) $(PACKAGE)

# CLEAN-BUILD MODE (dist)
dist: generate build
	@echo "--- [STEP] Cleaning intermediate files ---"
	rm -f $(BPF_GEN)
	@echo "--- [DONE] Directory is clean, binary is ready ---"

# CLEANUP
clean:
	@echo "--- [STEP] Removing all artifacts ---"
	rm -f $(BINARY) $(BPF_GEN)

# HELP
help:
	@echo "AVAILABLE COMMANDS:"
	@echo "  make        : Standard build (keeps generated files)"
	@echo "  make dist   : Clean build (deletes generated files after build)"
	@echo "  make clean  : Remove binary and all generated files"