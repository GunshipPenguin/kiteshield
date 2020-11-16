CFLAGS = -Wall -nostdlib -nostartfiles -nodefaultlibs -fno-builtin -c -I ..
ARCH_DIR = arch
HEADER_OUTPUT_DIR = loader_headers

PLATFORM_INDEPENDENT_SRCS = $(wildcard platform_independent/*.c)
PLATFORM_INDEPENDENT_OBJS = $(addprefix platform_independent/obj/, $(notdir $(PLATFORM_INDEPENDENT_SRCS:.c=.o)))

STUBS = $(HEADER_OUTPUT_DIR)/stub_x86_64.h

debug: CFLAGS += -DDEBUG_OUTPUT

all: output_dirs $(PLATFORM_INDEPENDENT_OBJS) $(STUBS)
debug: all

output_dirs:
	mkdir -p obj
	mkdir -p platform_independent/obj
	mkdir -p $(HEADER_OUTPUT_DIR)

platform_independent/obj/%.o: platform_independent/%.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf obj/
	rm -rf platform_independent/obj
	rm -rf $(HEADER_OUTPUT_DIR)


# -------------------------------------------------
#  Architechure loader specific make rules follow
# -------------------------------------------------

# -------------------------------------------------
#  x86-64
# -------------------------------------------------
X86_64_SRCS = $(wildcard arch/x86_64/*.[c,S] ../common/*.c)
X86_64_OBJS = $(addprefix obj/x86_64/, $(addsuffix .o, $(basename $(notdir $(X86_64_SRCS:.c=.o)))))

x86_64_output_dirs:
	mkdir -p obj/x86_64

obj/x86_64/%.o: arch/x86_64/%.c
	$(CC) $(CFLAGS) $< -o $@

obj/x86_64/%.o: ../common/%.c
	$(CC) $(CFLAGS) $< -o $@

obj/x86_64/%.o: arch/x86_64/%.S
	$(AS) $< -o $@

$(HEADER_OUTPUT_DIR)/stub_x86_64.h: x86_64_output_dirs $(X86_64_OBJS)
	$(LD) $(PLATFORM_INDEPENDENT_OBJS) $(X86_64_OBJS) -T $(ARCH_DIR)/x86_64/link.lds -o obj/x86_64/loader.bin
	cat obj/x86_64/loader.bin | python3 bin_to_header.py loader_x86_64 > $(HEADER_OUTPUT_DIR)/loader_x86_64.h

