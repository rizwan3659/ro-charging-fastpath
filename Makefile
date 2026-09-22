CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wshadow

SRC = src/diam.c src/baseline.c src/fast.c

all: charging-bench

charging-bench: $(SRC) src/bench.c src/*.h
	$(CC) $(CFLAGS) -o $@ $(SRC) src/bench.c

test_engine: $(SRC) tests/test_engine.c src/*.h
	$(CC) $(CFLAGS) -o $@ $(SRC) tests/test_engine.c

test: test_engine
	./test_engine

asan: CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
asan: clean test

valgrind: test_engine
	valgrind --error-exitcode=1 --leak-check=full -q ./test_engine

bench: charging-bench
	./charging-bench

clean:
	rm -f charging-bench test_engine

.PHONY: all test asan valgrind bench clean
