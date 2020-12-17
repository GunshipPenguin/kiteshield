.section .text
.global _start

_start:
  # Load function has the following signature
  # void load(void *entry_stacktop)
  mov %rsp, %rdi # entry_stacktop
  call load

  # Return value of load is the address of ld.so to jump to, store it
  push %rax

  # Start the runtime in a new thread
  call do_fork

  # Returning thread is the child, start the application in it
  pop %rbx
  jmp *%rbx

