.section .text
.global _start

_start:
  # Load function has the following signature
  # void load(void *entry_stacktop)
  mov %rsp, %rdi # entry_stacktop
  call load

  # Return value of load is entry of ld.so to jump to, keep it safe
  push %rax

  # Start the runtime in a new thread
  mov $57, %rax # fork
  syscall

  cmp $-1, %rax
  je exit

  cmp $0, %rax
  je child

  # In the parent, call into our decryption runtime
  call runtime_start
  jmp exit

child:
  # In the child, set ourselves up to be traced and jump to program entry
  call child_setup_ptrace

  cmp $-1, %eax
  je exit

  pop %rbx
  jmp *%rbx

exit:
  mov $60, %rax
  mov $0, %rdi
  syscall

