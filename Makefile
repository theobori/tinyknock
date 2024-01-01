CC = clang
BPFTOOL = bpftool

TARGET = tinyknock
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

SRC_DIR = src

USER_C = $(SRC_DIR)/main.c \
		 $(SRC_DIR)/configuration.c
USER_OBJ = $(USER_C:.c=.o)
USER_SKEL = $(SRC_DIR)/$(TARGET:=.skel.h)

BPF_C = $(SRC_DIR)/tinyknock.bpf.c
BPF_OBJ = $(BPF_C:.c=.o)

CFLAGS = -Wall 

all: $(TARGET) $(BPF_OBJ)

$(TARGET): $(USER_SKEL) $(USER_OBJ)
	$(CC) -Wall -o $(TARGET) $(USER_OBJ) -lbpf -lelf -lz -lcyaml

$(BPF_OBJ): %.o: $(BPF_C) $(SRC_DIR)/vmlinux.h
	$(CC) \
	    -target bpf \
	    -D __BPF_TRACING__ \
        -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(SRC_DIR)/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	$(RM) \
		$(BPF_OBJ) \
		$(USER_OBJ) \
		$(TARGET) \
		$(USER_SKEL)

fclean: clean
	$(RM) $(SRC_DIR)/vmlinux.h

re: fclean all

.PHONY: \
	all \
	clean \
	fclean \
	re
