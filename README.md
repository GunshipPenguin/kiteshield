# Kiteshield

A packer/protector for x86-64 ELF binaries on Linux. Kiteshield wraps ELF
binaries with multiple layers of encryption and injects them with loader code
that decrypts, maps, and executes the packed binary entirely in userspace. A
ptrace-based runtime engine ensures that only functions in the current call
stack are decrypted at any given time and additionally implements a variety of
anti-debugging techniques in order to make packed binaries as hard to
reverse-engineer as possible.

See the [Architecture](#architecture) and [Codebase Layout](#codebase-layout)
sections below for a bird's-eye view of how Kiteshield works.

Kiteshield is intended to be a fun academic exercise in binary obfuscation
rather than something that can be used in the real world given the source code,
and thus how it works, is public.

Named for [the shields](https://en.wikipedia.org/wiki/Kite_shield) preferred by
the Normans in the 11th century (alternatively: the kiteshields that are so
prevalent in Old School Runescape).

## Building Kiteshield

Kiteshield requires the [Bitdefender
disassembler](https://github.com/bitdefender/bddisasm) library to decode
instructions in the packer. It is included as a submodule at `packer/bddisasm`
. To build it from a fresh clone, run the following (note you will need to have
CMake installed):

```
git submodule update --init
cd packer/bddisasm
mkdir build
cd build
cmake ..
make
```

You can now build Kiteshield in release mode by running `make` from the top
level directory. Alternatively you can create a debug build with `make debug`.
Debug builds of Kiteshield disable all anti-debugging features and turn on the
loader's very verbose debug logging.

In order to debug the actual anti-debugging functionality, you can build
Kiteshield in debug mode with anti-debugging functionality turned *on* using
`make debug-antidebug`.

## Using Kiteshield

To pack a binary called `program` and output the packed binary to `packed.ks`,
run:

```
./packer/kiteshield program packed.ks
```

`packed.ks` can now be run and should be functionally equivalent to `program`,
but encrypted and hard to reverse engineer. Note that for layer 2 encryption to
be applied, the input binary *must not* be stripped as Kiteshield relies on the
symbol table being present. On most Linux distros, standard system utilities
(eg. `/bin/ls`) are generally stripped.

You can still however pack stripped binaries without layer 2 encryption using
the `-n` flag:

```
./packer/kiteshield -n program packed.ks
```

This will produce an output binary packed with only layer 1 encryption and the
runtime engine omitted.

## <a name="codebase-layout"></a> Codebase Layout

Kiteshield is composed of two separate parts. The packer is a regular C
application that reads, instruments, and encrypts input binaries. The loader is
a freestanding C application responsible for dynamic function decryption and
anti-debugging functionality that is injected into input binaries by the packer.
It receives initial control from the kernel, maps all appropriate segments of
the binary into memory (including the dynamic linker if applicable), and hands
off control to the application. The loader also contains the runtime engine,
which dynamically decrypts and encrypts functions as they are entered and exited
at runtime.

Since the loader receives initial control from the kernel (ie. before any shared
libraries would normally be mapped by the dynamic linker). It does not have
access to glibc and thus all needed functionality provided by glibc is
re-implemented in the loader code.

Packer and loader code can be found in the `packer/` and `loader/` directories
respectively. Code that is common to both can be found in the `common/`
directory. A brief overview of the important parts of the codebase is as
follows:

```
kiteshield
├── common                               # Code common to packer/loader
│   ├── include
│   │   ├── defs.h
│   │   ├── obfuscation.h
│   │   └── rc4.h
│   ├── obfuscation.c                    # Obfuscation utilities
│   └── rc4.c                            # RC4 stream cipher implementation
├── LICENSE
├── loader                               # Loader code
│   ├── anti_debug.c                     # Anti debugging functionality
│   ├── bin_to_header.py                 # Script to "headerize" a compiled loader for injecting
│   ├── debug.c                          # Printing / debugging functionality enabled in debug mode
│   ├── entry.S                          # Initial loader entry code
│   ├── include
│   │   ├── anti_debug.h
│   │   ├── debug.h
│   │   ├── elf_auxv.h
│   │   ├── obfuscated_strings.h         # Generated file produced by string_obfuscation.py
│   │   ├── signal.h
│   │   ├── string.h
│   │   ├── syscalls.h
│   │   └── types.h
│   ├── link.lds                         # Linker script for building loader
│   ├── loader.c                         # Binary loading / mapping code (userspace exec)
│   ├── Makefile
│   ├── runtime.c                        # Runtime engine code
│   ├── string.c                         # String utilities (eg. strncat)
│   ├── string_obfuscation.py            # String obfuscation helper script
│   └── syscalls.c                       # System call implementations in inline assembly
├── Makefile
├── packer                               # Packer code
│   ├── bddisasm                         # Bitdefender x86-64 decoding library (submodule)
│   ├── elfutils.c                       # ELF binary reading/writing wrappers
│   ├── include
│   │   └── elfutils.h
│   ├── kiteshield.c                     # Main packer code
│   └── Makefile
├── README.md
└── testing                              # Integration tests (see testing/README.md)
```

## <a name="architecture"></a> Architecture

Kiteshield wraps input ELF binaries in two (or one, if using the `-n` flag)
layers of RC4 encryption such that the binary on disk is fairly well obfuscated.
These layers are stripped off at runtime by the loader.

### Layer 1

The first layer of encryption (referred to in the codebase as the "outer layer")
consists of a single RC4 pass over the entire input binary. This is designed
primarily to fight static analysis. Due to the way the key is deobfuscated
(which is dependent on the loader code) the first layer of encryption also
effectively checksums the loader code before executing the packed binary, making
Kiteshield resistant to code patching.

### Layer 2

The second layer of encryption (referred to in the codebase as the "inner
layer") consists of individual encryption of almost every function in the input
binary (identified via the symbol table at pack-time). A ptrace-based runtime
engine is triggered on every function entry and exit via
replacement of each function's entry instruction and all its return instructions
with `int3` instructions (which deliver a `SIGTRAP` when executed). Upon
receiving a trap, the runtime engine looks up the current function and encrypts
or decrypts it as needed such that only functions within the current call stack
are decrypted at any point in time.

After stripping off layer 1, Kiteshield effectively re-implements the `exec`
syscall in userspace (See `loader/loader.c`. This technique is commonly referred
to in literature as a "userspace exec" or "userland exec".) to map the packed
binary into memory via a series of `mmap`/`mprotect` calls before forking and
handing control off to the packed binary in the child and the runtime engine in
the parent (which attaches to the child using ptrace).

In addition to encryption, Kiteshield's loader code also contains a number of
anti-debugging features designed to make it as difficult as possible to analyze
a running packed binary (See `loader/anti_debug.c` and
`loader/include/anti_debug.h`).

To give a concrete example of Kiteshield in action, consider the following
hello world program, which we will pack with Kiteshield in debug mode.

```c
#include <stdio.h>

int main()
{
  puts("Hello World!");
  return 0;
}
```

When packed in debug mode, loader code in packed binaries will log very verbose
debug information. The following is the log from a packed binary corresponding
to the above program. It has been annotated (and additional newlines added for
clarity) to provide a concrete example of Kiteshield in action:

```
$ ./packed.ks
# Stripping layer 1 encryption
[kiteshield] RC4 decrypting binary with key f31de2fd90ed703bac45991e6042da81
[kiteshield] decrypted 12336 bytes

# Mapping segments from packed binary program header table
[kiteshield] mapping LOAD section from packed binary at 800000000
[kiteshield] mapping LOAD section from packed binary at 800001000
[kiteshield] mapping LOAD section from packed binary at 800002000
[kiteshield] mapping LOAD section from packed binary at 800003000

# Mapping dynamic linker specified in INTERP header of packed binary
[kiteshield] mapping INTERP ELF at path /lib64/ld-linux-x86-64.so.2
[kiteshield] mapped LOAD section from fd at b00000000
[kiteshield] interpreter base address is b00000000
[kiteshield] mapped LOAD section from fd at b00001000
[kiteshield] mapped LOAD section from fd at b0001f000
[kiteshield] mapped extra space for static data (.bss) at b00029000 len 400
[kiteshield] mapped LOAD section from fd at b00027000
[kiteshield] binary base address is 800000000

# Modifying ELF auxiliary vector as needed for program execution
[kiteshield] taking 7fff734f8730 as auxv start
[kiteshield] replaced auxv entry 9 with value 34359742544 (0x800001050)
[kiteshield] replaced auxv entry 3 with value 34359738432 (0x800000040)
[kiteshield] replaced auxv entry 7 with value 47244640256 (0xb00000000)
[kiteshield] replaced auxv entry 5 with value 11 (0xb)
[kiteshield] finished mapping binary into memory
[kiteshield] control will be passed to packed app at b00001090

# Mapping done, forking, starting runtime in parent, and handing control to ld.so in child
[kiteshield] starting ptrace runtime
[kiteshield] number of trap points: 5
[kiteshield] number of encrypted functions: 3

# List of points in memory that have been instrumented with an int3 instruction
[kiteshield] list of trap points:
[kiteshield] 8000011ac value: c3, type: ret function: __libc_csu_init
[kiteshield] 800001150 value: 41, type: ent function: __libc_csu_init
[kiteshield] 800001050 value: 31, type: ent function: _start
[kiteshield] 80000114b value: c3, type: ret function: main
[kiteshield] 800001135 value: 55, type: ent function: main
[kiteshield] child: PTRACE_TRACEME was successful
[kiteshield] child: handing control to packed binary

# Program is executing, functions are logged on entry/exit
[kiteshield] entering function _start, decrypting with key de88a921e09d10d04d31889465e10ff6
[kiteshield] entering function __libc_csu_init, decrypting with key 9df70403e272381c16abd77c22eee9f3
[kiteshield] leaving function __libc_csu_init via ret at 8000011ac, not decrypting new function at 7f2a0bce502a (no record)
[kiteshield] entering function main, decrypting with key 856eb81e873f66bf1ac64e2a07791777
[kiteshield] leaving function main via ret at 80000114b, not decrypting new function at 7f2a0bce509b (no record)

# Actual program output
Hello World!

[kiteshield] child exited with status 0
```

## Testing

Kiteshield has an extensive set of integration tests to verify correctness
across several different platforms. See `testing/README.md` for details.

## License

[MIT](https://github.com/GunshipPenguin/kiteshield/blob/master/LICENSE) © Rhys Rustad-Elliott

