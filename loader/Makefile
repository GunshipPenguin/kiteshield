CFLAGS = -Wall -nostdlib -nostartfiles -nodefaultlibs -fno-builtin -c -I ..

SRCS = $(wildcard *.[c,S] ../common/*.c)
OBJS = $(addprefix obj/, $(addsuffix .o, $(basename $(notdir $(SRCS:.c=.o)))))

.PHONY: all output_dirs debug clean

debug: CFLAGS += -DDEBUG_OUTPUT

all: output_dirs loader_stub.h

debug: all

output_dirs:
	mkdir -p obj

loader_stub.h: $(OBJS)
	$(LD) $(OBJS) -T link.lds -o obj/loader.bin
	cat obj/loader.bin | python3 bin_to_header.py loader_x86_64 > loader_stub.h

obj/%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

obj/%.o: ../common/%.c
	$(CC) $(CFLAGS) $< -o $@

obj/%.o: %.S
	$(AS) $< -o $@

clean:
	rm -rf obj/

