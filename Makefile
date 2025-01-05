# Название eBPF-программы
EBPF_PROG := counter
OUTPUT_DIR := build
BPF_SRC := bpf/$(EBPF_PROG).c
BPF_OBJ := $(OUTPUT_DIR)/$(EBPF_PROG).o
CLANG_FLAGS := -O2 -target bpf -g -I/usr/include/x86_64-linux-gnu/ -I/usr/include/

# Проверка на наличие инструментов
.PHONY: check
check:
	@command -v clang >/dev/null 2>&1 || { echo >&2 "clang is required but not installed."; exit 1; }
	@command -v llc >/dev/null 2>&1 || { echo >&2 "llc is required but not installed."; exit 1; }
	@echo "All required tools are installed."

# Компиляция eBPF-программы
.PHONY: build
build: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	@mkdir -p $(OUTPUT_DIR)
	clang $(CLANG_FLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "eBPF program compiled: $(BPF_OBJ)"

.PHONY: load_stats
load_stats:
	bpftool prog load $(BPF_OBJ) /sys/fs/bpf/stats
	bpftool prog show pinned /sys/fs/bpf/stats

# Очистка
.PHONY: clean
clean:
	rm -rf $(OUTPUT_DIR)
	@echo "Cleaned build directory."

# Перекомпиляция
.PHONY: rebuild
rebuild: clean build

# Полный процесс: проверка + сборка
.PHONY: all
all: check build
