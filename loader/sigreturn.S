.global restorer

restorer:
  mov $15, %rax  # sigreturn
  syscall

