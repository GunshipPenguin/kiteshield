.section .text
.global _start

_start:
  # Load function has the following signature
  # void load(void *entry_stacktop)
  mov %rsp, %rdi # entry_stacktop
  call load

  # Return value of load is entry of ld.so to jump to, keep it safe
  mov %rax, %rbx

  # Start the runtime in a new thread
  mov $57, %rax # fork
  syscall

  cmp $-1, %rax
  je fork_failed

  cmp $0, %rax
  je child

  # In original thread, pass control to ld.so
  jmp *%rbx

fork_failed:
  mov $0, %rdi
  jmp exit

child:
  call runtime_start

  mov $60, %rax
  syscall
