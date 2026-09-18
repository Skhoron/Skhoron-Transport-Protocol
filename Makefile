CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Iinclude
SRC = src/router.c src/socks5.c src/stream.c src/main.c
BIN = stp
TEST_BIN = test_router

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC)

# Юнит-тесты router.c.
test: tests/test_router.c src/router.c
	$(CC) $(CFLAGS) -o $(TEST_BIN) tests/test_router.c src/router.c
	./$(TEST_BIN)

clean:
	rm -f $(BIN) $(TEST_BIN)

.PHONY: all test clean