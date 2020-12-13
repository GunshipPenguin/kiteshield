#include "common/include/defs.h"
#include "common/include/rc4.h"

#include "loader/include/types.h"
#include "loader/include/debug.h"
#include "loader/include/syscalls.h"
#include "loader/include/signal.h"
#include "loader/include/key_deobfuscation.h"

struct trap_point_info tp_info __attribute__((section(".tp_info")));

/* Defined in loader.c */
extern struct key_info obfuscated_key;

struct trap_point *get_tp(void *addr) {
  struct trap_point *tp;
  int i = 0;
  for (; i < tp_info.num; i++) {
    if (tp_info.arr[i].addr == addr) {
      tp = &tp_info.arr[i];
      break;
    }
  }

  DIE_IF_FMT(i == tp_info.num,
             "could not find trap point at %p, exiting", addr);
  return tp;
}

void set_byte_at_addr(pid_t pid, void *addr, uint8_t value)
{
  long word;
  long res = sys_ptrace(PTRACE_PEEKTEXT, pid, (void *) addr, &word);
  DIE_IF_FMT(res != 0, "PTRACE_PEEKTEXT failed with error %d", res);

  word &= (~0) << 8;
  word |= value;

  res = sys_ptrace(PTRACE_POKETEXT, pid, addr, (void *) word);
  DIE_IF_FMT(res < 0, "PTRACE_POKETEXT failed with error %d", res);
}

void single_step(pid_t pid)
{
  long res = sys_ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
  DIE_IF_FMT(res < 0, "PTRACE_SINGLESTEP failed with error %d", res);
  int wstatus;
  sys_wait4(&wstatus);

  DIE_IF_FMT(WIFEXITED(wstatus),
             "child exited with status %u during single step",
             WEXITSTATUS(wstatus));
  DIE_IF(!WIFSTOPPED(wstatus),
         "child was stopped unexpectedly during single step, exiting");
  DIE_IF_FMT(
      WSTOPSIG(wstatus) != SIGTRAP,
      "child was stopped by unexpected signal %u during single step, exiting",
      WSTOPSIG(wstatus));
}

void encrypt_decrypt_func(
    pid_t pid,
    struct trap_point *trap_point,
    struct key_info *key_info)
{
  struct rc4_state rc4;
  rc4_init(&rc4, key_info->key, sizeof(key_info->key));

  uint8_t *curr_addr = trap_point->func_start;
  size_t remaining = trap_point->func_end - trap_point->func_start;
  while (remaining > 0) {
    long word;
    long res = sys_ptrace(PTRACE_PEEKTEXT, pid, (void *) curr_addr, &word);
    DIE_IF_FMT(res != 0, "PTRACE_PEEKTEXT failed with error %d", res);

    int to_write = remaining > 8 ? 8 : remaining;
    for (int i = 0; i < to_write; i++) {
      word ^= ((long) rc4_get_byte(&rc4)) << (i * 8);
    }

    res = sys_ptrace(PTRACE_POKETEXT, pid, curr_addr, (void *) word);
    DIE_IF_FMT(res < 0, "PTRACE_POKETEXT failed with error %d", res);

    curr_addr += to_write;
    remaining -= to_write;
  }
}

void handle_trap(pid_t pid, int wstatus, struct key_info *key_info)
{
  long res;
  struct user_regs_struct regs;

  res = sys_ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_GETREGS failed with error %d", res);
  DIE_IF_FMT(WSTOPSIG(wstatus) != SIGTRAP,
             "child was stopped by signal %u at pc = %p, exiting",
             WSTOPSIG(wstatus), regs.ip);

  /* Back up the instruction pointer, replace the int3 byte with the original
   * program code, single step through the original instruction and replace
   * the int3 */
  regs.ip--;
  res = sys_ptrace(PTRACE_SETREGS, pid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_SETREGS failed with error %d", res);

  struct trap_point *tp = get_tp((void *) regs.ip);

  if (tp->is_ret) {
    DEBUG_FMT("leaving function starting at %p from %p, encrypting",
              tp->func_start, tp->addr);
    set_byte_at_addr(pid, (void *) regs.ip, tp->value);
    single_step(pid);
    encrypt_decrypt_func(pid, tp, key_info);
    set_byte_at_addr(pid, tp->func_start, 0xCC);
  } else {
    DEBUG_FMT("entering function at %p, decrypting",
              tp->func_start, tp->func_end);
    encrypt_decrypt_func(pid, tp, key_info);
    set_byte_at_addr(pid, (void *) regs.ip, tp->value);
    single_step(pid);
  }

  res = sys_ptrace(PTRACE_CONT, pid, NULL, NULL);
  DIE_IF_FMT(res < 0, "PTRACE_CONT failed with error %d", res);
}

void runtime_start()
{
  DEBUG("starting ptrace runtime");
  DEBUG_FMT("number of tp_info entries: %u", tp_info.num);

  struct key_info actual_key;
  loader_key_deobfuscate(&obfuscated_key, &actual_key);

#ifdef DEBUG_OUTPUT
  for (int i = 0; i < tp_info.num; i++) {
    struct trap_point tp = tp_info.arr[i];
    DEBUG_FMT(
        "tp_info entry %u: value = %hhx, addr = %p",
        i, tp.value, tp.addr);
  }
#endif

  while (1) {
    int wstatus;
    pid_t pid = sys_wait4(&wstatus);

    DIE_IF(pid == -1, "wait4 syscall failed");
    DIE_IF_FMT(WIFEXITED(wstatus),
               "child exited with status %u", WEXITSTATUS(wstatus));
    DIE_IF(!WIFSTOPPED(wstatus),
           "child was stopped unexpectedly, exiting");
    DIE_IF_FMT(WSTOPSIG(wstatus) != SIGTRAP,
               "child was stopped by unexpected signal %u, exiting",
               WSTOPSIG(wstatus));

    handle_trap(pid, wstatus, &actual_key);
  }
}

/* Called into by the child to setup ptrace just before handing off control
 * to the packed binary */
long child_setup_ptrace()
{
  long ret = sys_ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  DIE_IF(ret == -1, "child: sys_ptrace(PTRACE_TRACEME) failed");

  DEBUG("child: PTRACE_TRACEME was successful");
  DEBUG("child: handing control to packed binary");
  return ret;
}

