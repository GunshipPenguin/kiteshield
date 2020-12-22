#include "common/include/defs.h"
#include "common/include/rc4.h"

#include "loader/include/types.h"
#include "loader/include/debug.h"
#include "loader/include/syscalls.h"
#include "loader/include/signal.h"
#include "loader/include/key_deobfuscation.h"
#include "loader/include/anti_debug.h"

struct trap_point_info tp_info __attribute__((section(".tp_info")));

/* Defined in loader.c */
extern struct rc4_key obfuscated_key;

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

static struct function *get_fcn_at_addr(void *addr)
{
  for (int i = 0; i < tp_info.num; i++) {
    struct function *curr = &tp_info.arr[i].fcn;
    if (curr->start_addr <= addr && (curr->start_addr + curr->len) > addr) {
      return curr;
    }
  }

  return NULL;
}

static void set_byte_at_addr(pid_t pid, void *addr, uint8_t value)
{
  long word;
  long res = sys_ptrace(PTRACE_PEEKTEXT, pid, (void *) addr, &word);
  DIE_IF_FMT(res != 0, "PTRACE_PEEKTEXT failed with error %d", res);

  word &= (~0) << 8;
  word |= value;

  res = sys_ptrace(PTRACE_POKETEXT, pid, addr, (void *) word);
  DIE_IF_FMT(res < 0, "PTRACE_POKETEXT failed with error %d", res);
}

static void single_step(pid_t pid)
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

static void encrypt_decrypt_fcn(
    pid_t pid,
    struct function *fcn,
    struct rc4_key *key)
{
  struct rc4_state rc4;
  rc4_init(&rc4, key->bytes, sizeof(key->bytes));

  uint8_t *curr_addr = fcn->start_addr;
  size_t remaining = fcn->len;
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

static void *get_stack_ret_addr(pid_t pid)
{
  struct user_regs_struct regs;
  long res = sys_ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_GETREGS failed with error %d", res);

  long word;
  res = sys_ptrace(PTRACE_PEEKTEXT, pid, (void *) regs.sp, &word);
  DIE_IF_FMT(res < 0, "PTRACE_PEEKTEXT failed with error %d", res);

  return (void *) word;
}

static void handle_fcn_entry(
    pid_t pid,
    struct trap_point *tp,
    struct rc4_key *key)
{
  if (check_traced()) {
    sys_kill(pid, SIGKILL);
    DIE(TRACED_MSG);
  }

  DEBUG_FMT("entering function at %p, decrypting", tp->fcn.start_addr);

  /* Encrypt caller if needed */
  void *call_point_addr = get_stack_ret_addr(pid);
  struct function *caller_fcn = get_fcn_at_addr(call_point_addr);
  if (caller_fcn) {
    DEBUG_FMT("encrypting caller of %p at %p",
              tp->fcn.start_addr, caller_fcn->start_addr);
    encrypt_decrypt_fcn(pid, caller_fcn, key);
  }

  /* Decrypt callee */
  encrypt_decrypt_fcn(pid, &tp->fcn, key);
  set_byte_at_addr(pid, tp->addr, tp->value);
  single_step(pid);
}

static void handle_fcn_exit(
    pid_t pid,
    struct trap_point *tp,
    struct rc4_key *key)
{
  if (check_traced()) {
    sys_kill(pid, SIGKILL);
    DIE(TRACED_MSG);
  }

  DEBUG_FMT("leaving function starting at %p from %p",
            tp->fcn.start_addr, tp->addr);
  set_byte_at_addr(pid, tp->addr, tp->value);
  single_step(pid);
  set_byte_at_addr(pid, tp->addr, INT3);

  /* We've now executed the ret instruction, if we're still in the same
   * function (ie. recursion), don't do anything, otherwise, encrypt the
   * function we've returned from.
   */
  struct user_regs_struct regs;
  long res = sys_ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_GETREGS failed with error %d", res);

  struct function *returnee = get_fcn_at_addr((void *) regs.ip);
  if (returnee && returnee->start_addr != tp->fcn.start_addr) {
    DEBUG_FMT("encrypting function at %p since we're leaving it",
              tp->fcn.start_addr);
    encrypt_decrypt_fcn(pid, returnee, key);
    set_byte_at_addr(pid, tp->fcn.start_addr, INT3);
  }
#ifdef DEBUG_OUTPUT
  else if (!returnee) {
    DEBUG_FMT(
        "not encrypting function at ip=%p since we don't have a record of it",
        regs.ip);
  } else {
    DEBUG_FMT("not encrypting function at %p since it's returning to itself",
              returnee->start_addr);
  }
#endif
}

static void handle_trap(pid_t pid, int wstatus, struct rc4_key *key)
{
  if (check_traced()) {
    sys_kill(pid, SIGKILL);
    DIE(TRACED_MSG);
  }

  long res;
  struct user_regs_struct regs;

  res = sys_ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_GETREGS failed with error %d", res);
  DIE_IF_FMT(WSTOPSIG(wstatus) != SIGTRAP,
             "child was stopped by signal %u at pc = %p, exiting",
             WSTOPSIG(wstatus), regs.ip);

  /* Back up the instruction pointer, to the start of the int3 in preparation
   * for executing the original instruction */
  regs.ip--;
  res = sys_ptrace(PTRACE_SETREGS, pid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_SETREGS failed with error %d", res);

  struct trap_point *tp = get_tp((void *) regs.ip);
  if (tp->is_ret) {
    handle_fcn_exit(pid, tp, key);
  } else {
    handle_fcn_entry(pid, tp, key);
  }

  if (antidebug_signal_check()) {
    sys_kill(pid, SIGKILL);
    DIE(TRACED_MSG);
  }

  res = sys_ptrace(PTRACE_CONT, pid, NULL, NULL);
  DIE_IF_FMT(res < 0, "PTRACE_CONT failed with error %d", res);
}

void runtime_start()
{
  DEBUG("starting ptrace runtime");
  DEBUG_FMT("number of tp_info entries: %u", tp_info.num);

  struct rc4_key actual_key;
  loader_key_deobfuscate(&obfuscated_key, &actual_key);

  signal_antidebug_init();
#ifdef DEBUG_OUTPUT
  for (int i = 0; i < tp_info.num; i++) {
    struct trap_point tp = tp_info.arr[i];
    DEBUG_FMT(
        "tp_info entry %u: value = %hhx, addr = %p",
        i, tp.value, tp.addr);
  }
#endif

  /* debugger checks are scattered throughout the runtime to interfere with
   * debugger attaches as much as possible.
   */
  if (check_traced())
    DIE(TRACED_MSG);

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

    if (check_traced()) {
      sys_kill(pid, SIGKILL);
      DIE(TRACED_MSG);
    }

    if (antidebug_signal_check()) {
      sys_kill(pid, SIGKILL);
      DIE(TRACED_MSG);
    }

    handle_trap(pid, wstatus, &actual_key);
  }
}

void do_fork(void *entry)
{
  if (check_traced())
    DIE(TRACED_MSG);

  pid_t ret = sys_fork();
  DIE_IF_FMT(ret < 0, "fork failed with error %d", ret);

  if (ret != 0) {
    runtime_start();
    sys_exit(0); /* Only the child returns from do_clone */
  }

  ret = sys_ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  DIE_IF_FMT(ret < 0, "child: PTRACE_TRACEME failed with error %d", ret);

  DEBUG("child: PTRACE_TRACEME was successful");
  DEBUG("child: handing control to packed binary");
}

