CC       := gcc
CFLAGS   := -Wall -Wextra -O0 -g -fno-pic -no-pie
LDFLAGS  :=
DLFLAGS  := -ldl

SRC_DIR  := .
BIN_DIR  := bin

SRC := $(wildcard $(SRC_DIR)/*.c)
BINS := $(patsubst $(SRC_DIR)/%.c,$(BIN_DIR)/%,$(SRC))

all: $(BIN_DIR) $(BIN_DIR)/benign_hello $(BIN_DIR)/antidebug_ptrace \
     $(BIN_DIR)/antidebug_timing $(BIN_DIR)/mem_exec \
     $(BIN_DIR)/loader_dlopen $(BIN_DIR)/high_entropy_blob

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/benign_hello: $(SRC_DIR)/benign_hello.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/antidebug_ptrace: $(SRC_DIR)/antidebug_ptrace.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/antidebug_timing: $(SRC_DIR)/antidebug_timing.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/mem_exec: $(SRC_DIR)/mem_exec.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BIN_DIR)/loader_dlopen: $(SRC_DIR)/loader_dlopen.c
	$(CC) $(CFLAGS) -o $@ $< $(DLFLAGS) $(LDFLAGS)

$(BIN_DIR)/high_entropy_blob: $(SRC_DIR)/high_entropy_blob.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(BIN_DIR)
