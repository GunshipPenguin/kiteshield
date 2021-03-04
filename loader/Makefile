CFLAGS = -Wall -std=gnu99 -fno-pie -nostdlib -nostartfiles -nodefaultlibs -fno-builtin -c -I ..
LDFLAGS = -no-pie

SRCS = $(wildcard *.[c,S] ../common/*.c)
OBJS = $(addprefix out/, $(addsuffix .o, $(basename $(notdir $(SRCS:.c=.o)))))

OBFUSCATED_STRINGS_FILE = include/obfuscated_strings.h

.PHONY: all output_dirs debug clean

debug: CFLAGS += -DDEBUG_OUTPUT -DNO_ANTIDEBUG
debug-antidebug: CFLAGS += -DDEBUG_OUTPUT

all: output_dirs $(OBFUSCATED_STRINGS_FILE) out/loader_header.h

debug: all
debug-antidebug: all

output_dirs:
	mkdir -p out

$(OBFUSCATED_STRINGS_FILE):
	python3 string_obfuscation.py > $(OBFUSCATED_STRINGS_FILE)

out/loader_header.h: $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -T link.lds -o out/loader-elf
	objcopy -O binary out/loader-elf out/loader.bin
	cat out/loader.bin | python3 bin_to_header.py GENERATED_LOADER > out/generated_loader.h

out/%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

out/%.o: ../common/%.c
	$(CC) $(CFLAGS) $< -o $@

out/%.o: %.S
	$(AS) $< -o $@

clean:
	rm -rf out/
	rm -f $(OBFUSCATED_STRINGS_FILE)

