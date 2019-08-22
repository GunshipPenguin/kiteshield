# Kiteshield

An anti-reverse-engineering tool for ELF binaries on Linux. Intended to be a
fun academic exercise in binary obfuscation rather than a real obfscuator
(given that the source code, and thus how it works, is public). See section
below for a high level overview of how it works.

Currently in earlyish development. Directory layout is subject to change, but
currently arranged as follows:

- src/loaders: Loader code (code that decrypts, maps and hands off control
to the actual binary at runtime)
    - src/loaders/arch: Architecture specific loaders (currently only x86-64 is
    supported)
    - src/loaders/platform\_independent: Platform independent loader code
    - src/loaders/loader\_headers: "compiled" loader headers (ie. header files
    containing a definition of the form char array[n] = {...} with the array
    containing an architecture specific loader as raw machine code. This is
    used by the packer code to inject into an existing ELF binary.
- src/packer: Packer code (code that injects the loader into an unhardened
binary)
- src/common: Functionality that needs to be shared across loader/packer code

## How it works

Kiteshield takes as input any existing Linux ELF binary for whose architecture
it supports (only x86-64 at the moment). It produces a binary that is
functionally equivalent, but should be hard to reverse engineer. This is
accomplished by encrypting it with a stream cipher and injecting it with a 
loader (also referred to as a stub or stub loader in other literature), that 
dynamically decrypts it on the fly during execution.

