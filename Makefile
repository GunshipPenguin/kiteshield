SRC_DIR = $(shell pwd)/src
OBJ_DIR = obj

SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(addprefix $(OBJ_DIR)/,$(notdir $(SRC_FILES:.c=.o)))

CC_FLAGS ?= -std=c99 -Wall -I $(SRC_DIR)/include -g

BIN_NAME = kiteshield

all: stubs $(OBJ_DIR) $(BIN_NAME)

stubs:
	python3 build_stubs.py

$(BIN_NAME): $(OBJ_FILES)
	$(CC) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CC_FLAGS) -c -o $@ $<

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR)
	rm -f $(BIN_NAME)

.PHONY: stubs clean
