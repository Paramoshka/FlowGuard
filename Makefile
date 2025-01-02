# Define directories
SRC_DIR := bpf
BUILD_DIR := build

# Find the path to bpf_helpers.h and asm/types.h dynamically
LIBBPF_INCLUDE := $(shell find /usr/src/linux-headers-$(shell uname -r) -type d -name "libbpf" | head -n 1)/include
#KERNEL_INCLUDE := /usr/src/linux-headers-$(shell uname -r)/include
USER_INCLUDE := /usr/include/$(shell uname -i)-linux-gnu

# Compiler and flags
CLANG := clang
CFLAGS := -v -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
          -I$(LIBBPF_INCLUDE)  -I$(USER_INCLUDE)

# Source and object files
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Default target
all: $(BUILD_DIR) $(OBJS)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CLANG) $(CFLAGS) -c $< -o $@

# Clean target
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean