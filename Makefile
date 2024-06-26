CC = clang

TARGET = tinyknock
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

SRC_DIR = src

USER_C = $(SRC_DIR)/main.c \
		 $(SRC_DIR)/configuration/configuration.c \
		 $(SRC_DIR)/argparse/argparse.c \
		 $(SRC_DIR)/arguments/arguments.c \
		 $(SRC_DIR)/common/common.c \
		 $(SRC_DIR)/rule/rule.c

USER_OBJ = $(USER_C:.c=.o)
USER_SKEL = $(SRC_DIR)/$(TARGET:=.skel.h)

BPF_C = $(SRC_DIR)/tinyknock.bpf.c
BPF_OBJ = $(BPF_C:.c=.o)

CFLAGS = -Wall -g

all: $(TARGET) $(BPF_OBJ)

$(TARGET): $(USER_OBJ)
	$(CC) -Wall -o $(TARGET) $(USER_OBJ) -lbpf -lelf -lz -lcyaml -lxdp

$(BPF_OBJ): %.o: $(BPF_C)
	$(CC) \
	    -target bpf \
        -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

clean:
	$(RM) $(USER_OBJ)

fclean: clean
	$(RM) \
		$(BPF_OBJ) \
		$(TARGET)

re: fclean all

.PHONY: \
	all \
	clean \
	fclean \
	re
