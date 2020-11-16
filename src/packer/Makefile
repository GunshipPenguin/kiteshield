CFLAGS = -Wall -I ..

SRCS = $(wildcard *.c ../common/*.c)
OBJS = $(addprefix ./obj/, $(notdir $(SRCS:.c=.o)))
BIN_NAME = kiteshield

all: output_dirs $(OBJS)
	$(CC) $(OBJS) -o $(BIN_NAME)

output_dirs:
	mkdir -p obj

obj/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

obj/%.o: ../common/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BIN_NAME)
	rm -rf obj/
