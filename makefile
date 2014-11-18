LIB_PATH = /usr/lib/
INC_PATH = /usr/include/libnl3
LDFLAGS = -lnl-3 -lrt -lnl-route-3
CC=gcc
CFLAGS= -g -Wall

ARCH:=$(shell uname -m)

BUILD_PATH=build/$(ARCH)/
SRC_PATH=src/
BIN_PATH=bin/$(ARCH)/
TEST_PATH=test/
TEST_BIN=test_bin/

OBJS = $(BUILD_PATH)network.o \
       $(BUILD_PATH)link_monitor.o \
       $(BUILD_PATH)interface.o \
       $(BUILD_PATH)util.o \
       $(BUILD_PATH)config.o \
       $(BUILD_PATH)queue.o \
       $(BUILD_PATH)list.o


TESTS = $(TEST_PATH)test_link_monitor

all: mpdd

run_tests: $(TESTS)
	@$(TEST_BIN)test_link_monitor || (echo "Test Link Monitor Failed $$?"; exit 1)
	@echo "Test Link Monitor Passed"

test/simple_link_monitor: $(TEST_PATH)simple_link_monitor.c $(OBJS)
	$(CC) $(CFLAGS) -D DEBUG_HIGH -o $(TEST_BIN)simple_link_monitor $(TEST_PATH)simple_link_monitor.c $(OBJS) -I$(INC_PATH) $(LDFLAGS) -lpthread


test/test_link_monitor: $(TEST_PATH)test_link_monitor.c $(OBJS)
	$(CC) $(CFLAGS) -D DEBUG_HIGH -o $(TEST_BIN)test_link_monitor $(TEST_PATH)test_link_monitor.c $(OBJS) -I$(INC_PATH) $(LDFLAGS) -lpthread

build_arch_dir:
	@if [ ! -d "$(BUILD_PATH)" ]; then mkdir -p $(BUILD_PATH); fi;

bin_arch_dir:
	@if [ ! -d "$(BIN_PATH)" ]; then mkdir -p $(BIN_PATH); fi;

mpdd: build_arch_dir bin_arch_dir $(SRC_PATH)mpdd.c $(OBJS)
	$(CC) $(CFLAGS) -o $(BIN_PATH)mpdd $(SRC_PATH)mpdd.c $(OBJS) -I$(INC_PATH) $(LDFLAGS) -lpthread -lconfig

$(BUILD_PATH)network.o: $(SRC_PATH)network.c $(SRC_PATH)network.h
	$(CC) $(CFLAGS) -c $(SRC_PATH)network.c -I$(INC_PATH) $(LDFLAGS) -o $(BUILD_PATH)network.o

$(BUILD_PATH)link_monitor.o: $(SRC_PATH)link_monitor.c $(SRC_PATH)link_monitor.h
	$(CC) $(CFLAGS) -c $(SRC_PATH)link_monitor.c -I$(INC_PATH) $(LDFLAGS) -o $(BUILD_PATH)link_monitor.o

$(BUILD_PATH)interface.o: $(SRC_PATH)interface.c $(SRC_PATH)interface.h
	$(CC) $(CFLAGS) -c $(SRC_PATH)interface.c -I$(INC_PATH) $(LDFLAGS) -o $(BUILD_PATH)interface.o

$(BUILD_PATH)config.o: $(SRC_PATH)config.c $(SRC_PATH)config.h
	$(CC) $(CFLAGS) -c $(SRC_PATH)config.c -I$(INC_PATH) -lconfig -o $(BUILD_PATH)config.o

$(BUILD_PATH)util.o: $(SRC_PATH)util.c $(SRC_PATH)util.h
	$(CC) $(CFLAGS) -c $(SRC_PATH)util.c -I$(INC_PATH) $(LDFLAGS) -o $(BUILD_PATH)util.o

$(BUILD_PATH)queue.o: $(SRC_PATH)queue.c $(SRC_PATH)queue.h
	$(CC) $(CFLAGS) -c $(SRC_PATH)queue.c -o $(BUILD_PATH)queue.o

$(BUILD_PATH)list.o: $(SRC_PATH)list.c $(SRC_PATH)list.h
	$(CC) $(CFLAGS) -c $(SRC_PATH)list.c -o $(BUILD_PATH)list.o

clang:
	clang -fsyntax-only src/* -I$(INC_PATH) $(LDFLAGS)

clean:
	@echo "Cleaning..."
	- rm $(BUILD_PATH)* $(BIN_PATH)*

