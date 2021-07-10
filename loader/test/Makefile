CFLAGS = -Wall -g -fno-pie -nostdlib -Werror -std=gnu99 -c -I ../..
LDFLAGS = -no-pie

SRCS = $(wildcard *.c)
OBJS = $(filter-out ../out/rt/entry.o, $(wildcard ../out/rt/*.o))
TEST_OBJS = $(addprefix out/, $(addsuffix .o, $(basename $(notdir $(SRCS:.c=.o)))))

.PHONY: all output-dirs debug debug-antidebug clean

all: output-dirs loadertest

loadertest: $(OBJS) $(TEST_OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(TEST_OBJS) -o out/loadertest
	./out/loadertest

out/%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

out/%.o: ../common/%.c
	$(CC) $(CFLAGS) $< -o $@

out/%.o: %.S
	$(CC) -c $< -o $@

output-dirs:
	mkdir -p out

clean:
	rm -rf out/
