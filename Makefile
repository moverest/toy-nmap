BUILD_DIR = build
SRC_DIR = src

CFLAGS = -Wall -std=gnu99 -ldl
CFLAGS_DEBUG = -g -DDEBUG
CC = gcc $(CFLAGS)

.PHONY: all
all: $(BUILD_DIR) $(BUILD_DIR)/main

.PHONY: tests
tests: $(BUILD_DIR) $(foreach f, main, $(BUILD_DIR)/$f)
.PHONY: debug
debug: CFLAGS += $(CFLAGS_DEBUG)
debug: all tests

.PHONY: clean
clean:
	rm -rvf $(BUILD_DIR) main

$(BUILD_DIR)/main: $(foreach f, tcputils ping scan udputils, $(BUILD_DIR)/$f.o)

$(BUILD_DIR)/%: $(BUILD_DIR)/%.o
	$(CC) -o $@ $(filter %.o, $^) $(LD_FLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) -c $< -o $@

$(BUILD_DIR)/ping.o: $(SRC_DIR)/ping.h
$(BUILD_DIR)/tcputils.o: $(SRC_DIR)/tcputils.h
$(BUILD_DIR)/udputils.o: $(SRC_DIR)/udputils.h
$(BUILD_DIR)/scan.o: $(SRC_DIR)/scan.h

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
