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

#ifdef USE_RUNTIME
  # Fork, starting the runtime in the parent process and returning in the child
  call do_fork

  # We've now forked. The runtime is running in our parent and will not return.
  # here. Only the child will execute the code below.
#endif

  # The x86-64 SysV ABI specifies that %rdx contains the address of a function
  # to be registered by libc with atexit upon entry (or 0 to indicate no
  # function). In practice, Linux always sets this to 0 (see ELF_PLAT_INIT
  # macro in kernel sources) before handing control to userspace. This register
  # was probably clobbered by the calls to load/do_fork above, so zero it
  # before we jump to program entry so the libc doesn't register a garbage
  # address as an exit handler.
  xor %edx, %edx

  # While we're at it, zero all the other non-privileged registers (besides
  # %rbx, which is holding the program entry point to jump to) that Linux
  # normally zeros before handing control to userspace. Unlike %rdx, this isn't
  # strictly necessary, but we'll do it anyways to make things as deterministic
  # as possible.
  xor %eax, %eax
  xor %ecx, %ecx
  xor %esi, %esi
  xor %edi, %edi
  xor %ebp, %ebp
  xor %r8d, %r8d
  xor %r9d, %r9d
  xor %r10d, %r10d
  xor %r11d, %r11d
  xor %r12d, %r12d
  xor %r13d, %r13d
  xor %r14d, %r14d
  xor %r15d, %r15d

  pop %rbx
  jmp *%rbx

