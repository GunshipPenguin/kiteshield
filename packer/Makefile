CFLAGS = -Wall -std=gnu99 -I .. -I bddisasm/inc
LDFLAGS = -Lbddisasm/bin/x64/Release -l:libbddisasm.a

SRCS = $(wildcard *.c ../common/*.c)
OBJS = $(addprefix ./obj/, $(notdir $(SRCS:.c=.o)))
BIN_NAME = kiteshield

.PHONY: all debug output_dirs clean

debug: CFLAGS += -g -DDEBUG_OUTPUT -DNO_ANTIDEBUG
debug-antidebug: CFLAGS += -g -DDEBUG_OUTPUT

all: output_dirs $(OBJS)
	$(CC) $(OBJS) -o $(BIN_NAME) $(LDFLAGS)

debug: all
debug-antidebug: all

output_dirs:
	mkdir -p obj

obj/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

obj/%.o: ../common/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BIN_NAME)
	rm -rf obj/
