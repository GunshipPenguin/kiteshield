#include "common/include/defs.h"
#include "common/include/rc4.h"

#include "loader/include/types.h"
#include "loader/include/debug.h"
#include "loader/include/syscalls.h"
#include "loader/include/signal.h"
#include "loader/include/key_deobfuscation.h"
#include "loader/include/anti_debug.h"

#define FCN_ARR_START ((struct function *) (((struct trap_point *) tp_info.data) + tp_info.ntps))
#define FCN(tp) ((struct function *) (FCN_ARR_START + tp->fcn_i))

struct trap_point_info tp_info __attribute__((section(".tp_info")));

/* Defined in loader.c */
extern struct rc4_key obfuscated_key;

struct trap_point *get_tp(void *addr) {
  struct trap_point *arr = (struct trap_point *) tp_info.data;
  for (int i = 0; i < tp_info.ntps; i++) {
    if (arr[i].addr == addr) {
      return &arr[i];
    }
  }

  return NULL;
}

static struct function *get_fcn_at_addr(void *addr)
{
  struct function *arr = FCN_ARR_START;

  for (int i = 0; i < tp_info.nfuncs; i++) {
    struct function *curr = &arr[i];
    if (curr->start_addr <= addr && (curr->start_addr + curr->len) > addr)
      return curr;
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

  DIE_IF_FMT(pid == -1, "wait4 syscall failed with error %d", pid);
  DIE_IF_FMT(
      WIFEXITED(wstatus),
      "child exited with status %u during single step",
      WEXITSTATUS(wstatus));
  DIE_IF_FMT(
      WIFSIGNALED(wstatus),
      "child was killed by signal, %u during single step, exiting",
      WTERMSIG(wstatus));
  DIE_IF(
      !WIFSTOPPED(wstatus),
      "child was stopped unexpectedly during single step, exiting");
  DIE_IF_FMT(
      WSTOPSIG(wstatus) != SIGTRAP,
      "child was stopped by unexpected signal %u during single step, exiting",
      WSTOPSIG(wstatus));
}

static void rc4_xor_fcn(
    pid_t pid,
    struct function *fcn)
{
  struct rc4_state rc4;
  rc4_init(&rc4, fcn->key.bytes, sizeof(fcn->key.bytes));

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

    res = sys_ptrace(PTRACE_PEEKTEXT, pid, (void *) curr_addr, &word);
    DIE_IF_FMT(res != 0, "PTRACE_PEEKTEXT failed with error %d", res);

    curr_addr += to_write;
    remaining -= to_write;
  }
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
  struct function *fcn = FCN(tp);

  DEBUG_FMT("entering function %s, decrypting with key %s", fcn->name,
      STRINGIFY_KEY(&fcn->key));

  /* Decrypt callee */
  rc4_xor_fcn(pid, fcn);
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

  set_byte_at_addr(pid, tp->addr, tp->value);
  single_step(pid);
  set_byte_at_addr(pid, tp->addr, INT3);

  /* We've now executed the ret or jmp instruction, if we're still in the same
   * function (which either means returning from a recursive call for a ret or
   * an in-function jmp), don't do anything. Otherwise, encrypt the function
   * we've just returned from.
   */
  struct user_regs_struct regs;
  long res = sys_ptrace(PTRACE_GETREGS, pid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_GETREGS failed with error %d", res);

  struct function *prev_fcn = FCN(tp);
  struct function *new_fcn = get_fcn_at_addr((void *) regs.ip);
  if (new_fcn != NULL && new_fcn != prev_fcn) {
    DEBUG_FMT("leaving function %s for %s via %s at %p, encrypting with key %s",
              prev_fcn->name, new_fcn->name, tp->type == TP_JMP ? "jmp" : "ret",
              tp->addr, STRINGIFY_KEY(&prev_fcn->key));

    /* Encrypt prev_fcn (function we're leaving) */
    rc4_xor_fcn(pid, prev_fcn);
    set_byte_at_addr(pid, prev_fcn->start_addr, INT3);

    /* If we're entering a function via an out-of-function jmp, we assume it's
     * not in the current call stack, and thus we must decrypt it. */
    if (tp->type == TP_JMP) {
      rc4_xor_fcn(pid, new_fcn);
      struct trap_point *new_fcn_tp = get_tp(new_fcn->start_addr);
      if (new_fcn_tp != NULL)
        set_byte_at_addr(pid, new_fcn->start_addr, new_fcn_tp->value);
    }
  } else if (!new_fcn) {
    DEBUG_FMT(
        "leaving function %s via %s at %p, not decrypting new function at %p (no record)",
        prev_fcn->name, tp->type == TP_JMP ? "jmp" : "ret", tp->addr, regs.ip);

    /* Encrypt prev_fcn (function we're leaving) */
    rc4_xor_fcn(pid, prev_fcn);
    set_byte_at_addr(pid, prev_fcn->start_addr, INT3);
  }
#ifdef DEBUG_OUTPUT
  else {
     DEBUG_FMT("hit trap point in %s at %p, but did not leave function (now at %p) (%s), continuing",
               prev_fcn->name, tp->addr, regs.ip,
               tp->type == TP_JMP ? "internal jmp" : "recursive return");
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

  /* Back up the instruction pointer, to the start of the int3 in preparation
   * for executing the original instruction */
  regs.ip--;
  res = sys_ptrace(PTRACE_SETREGS, pid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_SETREGS failed with error %d", res);

  struct trap_point *tp = get_tp((void *) regs.ip);
  if (tp->type == TP_FCN_ENTRY) {
    handle_fcn_entry(pid, tp, key);
  } else {
    handle_fcn_exit(pid, tp, key);
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
  DEBUG_FMT("number of trap points: %u", tp_info.ntps);
  DEBUG_FMT("number of encrypted functions: %u", tp_info.nfuncs);

  struct rc4_key actual_key;
  loader_key_deobfuscate(&obfuscated_key, &actual_key);

  signal_antidebug_init();

#ifdef DEBUG_OUTPUT
  DEBUG("list of trap points:");
  for (int i = 0; i < tp_info.ntps; i++) {
    struct trap_point *tp = ((struct trap_point *) tp_info.data) + i;
    const char *type = tp->type == TP_JMP ? "jmp" : tp->type == TP_RET ? "ret" : "ent";
    DEBUG_FMT("%p value: %hhx, type: %s function: %s",
              tp->addr, tp->value, type, FCN(tp)->name);
  }
#endif

  /* debugger checks are scattered throughout the runtime to interfere with
   * debugger attaches as much as possible.
   */
  if (check_traced())
    DIE(TRACED_MSG);

  /* Do the prctl down here so a reverse engineer will have to defeat the
   * preceeding check_traced() call before prctl shows up in a strace */
  antidebug_set_nondumpable();

  while (1) {
    int wstatus;
    pid_t pid = sys_wait4(&wstatus);

    DIE_IF_FMT(pid == -1, "wait4 syscall failed with error %d", pid);

    if (WIFEXITED(wstatus)) {
      DEBUG_FMT("child exited with status %u", WEXITSTATUS(wstatus));
      sys_exit(WEXITSTATUS(wstatus));
    }

    DIE_IF_FMT(
        WIFSIGNALED(wstatus),
        "child was killed by signal, %u exiting", WTERMSIG(wstatus));
    DIE_IF(
        !WIFSTOPPED(wstatus),
        "child was stopped unexpectedly, exiting");
    DIE_IF_FMT(
        WSTOPSIG(wstatus) != SIGTRAP,
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

