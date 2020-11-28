CFLAGS = -Wall -I .. -I bddisasm/inc
LDFLAGS = -Lbddisasm/bin/x64/Release -l:libbddisasm.a

SRCS = $(wildcard *.c ../common/*.c)
OBJS = $(addprefix ./obj/, $(notdir $(SRCS:.c=.o)))
BIN_NAME = kiteshield

all: output_dirs $(OBJS)
	$(CC) $(OBJS) -o $(BIN_NAME) $(LDFLAGS)

output_dirs:
	mkdir -p obj

obj/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

obj/%.o: ../common/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BIN_NAME)
	rm -rf obj/
