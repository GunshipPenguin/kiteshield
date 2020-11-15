.section .text
.global _start

_start:
    # Load function has the following signature
    # void load(void *entry_stacktop)
    mov %rsp, %rdi # entry_stacktop
    call load

    # Before we jump to program entry, zero out all registers in case
    # the mapping code modified them. ld.so or any other binary
    # shouldn't assume that these are zero, but this should make
    # things more deterministic.
    mov $0, %rcx
    mov $0, %rbx
    mov $0, %rdx
    mov $0, %rdx
    mov $0, %rsi
    mov $0, %rdi
    mov $0, %rbp

    mov $0, %r8
    mov $0, %r9
    mov $0, %r10
    mov $0, %r11
    mov $0, %r12
    mov $0, %r13
    mov $0, %r14
    mov $0, %r15

    jmp %rax

