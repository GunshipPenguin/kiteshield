.section .text
.global _start

_start:
    # Load function has the following signature
    # void load(void *entry_stacktop)
    mov %rsp, %rdi # entry_stacktop
    call load

    jmp exit_success

exit_success:
    mov $60, %rax
    mov $0, %rdi
    syscall
