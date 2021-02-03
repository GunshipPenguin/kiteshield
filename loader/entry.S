.section .text
.global _start

_start:
  # Per the SysV ABI, the value of %rbp is undefined upon getting control from
  # the kernel and should be set to 0 manually to mark the deepest stack frame.
  xor %ebp, %ebp

  # Load function has the following signature
  # void load(void *entry_stacktop)
  mov %rsp, %rdi # entry_stacktop
  call load

  # Return value of load is the address of ld.so to jump to, store it
  push %rax

  # Start the runtime in a new thread
  call do_fork

  # We've now forked. The runtime is running in our parent and will not return.
  # here. Only the child will execute the code below.

  # The x86-64 SysV ABI specifies that %rdx contains the address of a function
  # to be registered by libc with atexit upon entry (or 0 to indicate no
  # function). In practice, Linux always sets this to 0 (see ELF_PLAT_INIT
  # macro in kernel sources) before handing control to userspace. This register
  # was probably clobbered by the calls to load/do_fork above, so zero it
  # before we jump to program entry so the libc doesn't register a garbage
  # address as an exit handler.
  mov $0, %rdx

  # While we're at it, zero all the other non-privileged registers (besides
  # %rbx, which is holding the program entry point to jump to) that Linux
  # normally zeros before handing control to userspace. Unlike %rdx, this isn't
  # strictly necessary, but we'll do it anyways to make things as deterministic
  # as possible.
  mov $0, %rcx
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

  pop %rbx
  jmp *%rbx

