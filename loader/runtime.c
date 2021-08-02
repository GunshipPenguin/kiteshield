#ifdef USE_RUNTIME

#include "common/include/defs.h"
#include "common/include/obfuscation.h"
#include "common/include/rc4.h"

#include "loader/include/errno.h"
#include "loader/include/types.h"
#include "loader/include/debug.h"
#include "loader/include/syscalls.h"
#include "loader/include/obfuscated_strings.h"
#include "loader/include/signal.h"
#include "loader/include/string.h"
#include "loader/include/malloc.h"
#include "loader/include/anti_debug.h"

/* See PTRACE_SETOPTIONS in ptrace manpage */
#define PTRACE_EVENT_PRESENT(wstatus, event) \
  ((wstatus) >> 8 == (SIGTRAP | (event) << 8))

#define FCN_ARR_START ((struct function *) (((struct trap_point *) rt_info.data) + rt_info.ntraps))
#define FCN_FROM_TP(tp) ((struct function *) (FCN_ARR_START + tp->fcn_i))

#define FCN_INC_REF(thread, fcn) \
  do { \
    ((thread)->as->fcn_ref_arr[(fcn)->id]++); \
  } while (0)

#define FCN_DEC_REF(thread, fcn) \
  do { \
    ((thread)->as->fcn_ref_arr[(fcn)->id]--); \
  } while(0)

#define FCN_ENTER(thread, fcn) \
  do { \
    bt_push(thread, fcn); \
    FCN_INC_REF(thread, fcn); \
  } while (0)

#define FCN_EXIT(thread, fcn) \
  do { \
    bt_pop(thread); \
    FCN_DEC_REF(thread, fcn); \
  } while (0)

#define FCN_REFCNT(thread, fcn) ((thread)->as->fcn_ref_arr[(fcn)->id])

struct runtime_info rt_info __attribute__((section(".rt_info")));

/* Function encryption data needs to be maintained per address space and not
 * per-thread as multiple threads could be executing in the same address space.
 */
struct address_space {
  int refcnt;

  /* Array of "reference counts" indexed by function id of functions in this
   * address space. When a thread enters a function, we bump its refcount and
   * when a thread leaves, we decrement it. Thus, a function's reference count
   * indicates the number of threads having it in their stack trace. When this
   * reaches 0, that indicates we can safely encrypt the function as no thread
   * will return to it in the future, expecting it to be decrypted.
   *
   * 16 bit integers were chosen to save a bit of space since this array can be
   * large. This still allows 65535 threads, which ought to be enough for
   * anybody.
   */
  uint16_t *fcn_ref_arr;
};

/* Structure used to keep track of the current backtrace of each thread. A
 * linked list of these is maintained in each thread context and on thread
 * exit, functions that are still in the thread's backtrace have their
 * reference counts decremented and are re-encrypted as needed.
 */
struct backtrace {
  struct function *fcn;
  struct backtrace *next;
};

/* Information about an executing thread of execution (ie. something created
 * via fork/vfork/clone. A linked list of these is maintained on kiteshield's
 * heap for every thread in existence.
 */
struct thread {
  pid_t tgid;
  pid_t tid;
  int has_wait_prio; /* See fair_wait_threads */
  struct backtrace *bt;
  struct address_space *as;
  struct thread *next;
};

struct thread_list {
  size_t size;
  struct thread *head;
};

struct trap_point *get_tp(uint64_t addr) {
  struct trap_point *arr = (struct trap_point *) rt_info.data;
  for (int i = 0; i < rt_info.ntraps; i++) {
    if (arr[i].addr == addr) {
      return &arr[i];
    }
  }

  return NULL;
}

static struct function *get_fcn_at_addr(uint64_t addr)
{
  struct function *arr = FCN_ARR_START;

  for (int i = 0; i < rt_info.nfuncs; i++) {
    struct function *curr = &arr[i];
    if (curr->start_addr <= addr && (curr->start_addr + curr->len) > addr)
      return curr;
  }

  return NULL;
}

static void set_byte_at_addr(pid_t tid, uint64_t addr, uint8_t value)
{
  long word;
  long res = sys_ptrace(PTRACE_PEEKTEXT, tid, (void *) addr, &word);
  DIE_IF_FMT(res != 0, "PTRACE_PEEKTEXT failed with error %d", res);

  word &= (~0) << 8;
  word |= value;

  res = sys_ptrace(PTRACE_POKETEXT, tid, (void *) addr, (void *) word);
  DIE_IF_FMT(res < 0, "PTRACE_POKETEXT failed with error %d", res);
}

static void single_step(pid_t tid)
{
  long res;
  int wstatus;

retry:
  res = sys_ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL);
  DIE_IF_FMT(res < 0, "PTRACE_SINGLESTEP failed with error %d", res);
  sys_wait4(tid, &wstatus, __WALL);

  DIE_IF_FMT(tid < 0, "wait4 syscall failed with error %d", tid);
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

  if (WSTOPSIG(wstatus) == SIGSTOP) {
    /* stopped by runtime for concurrency purposes, there should be a SIGTRAP
     * in the queue next */
    goto retry;
  }

  DIE_IF_FMT(
      WSTOPSIG(wstatus) != SIGTRAP,
      "child was stopped by unexpected signal %u during single step, exiting",
      WSTOPSIG(wstatus));
}

static void rc4_xor_fcn(
    pid_t tid,
    struct function *fcn)
{
  struct rc4_state rc4;
  rc4_init(&rc4, fcn->key.bytes, sizeof(fcn->key.bytes));

  uint8_t *curr_addr = (uint8_t *) fcn->start_addr;
  size_t remaining = fcn->len;
  while (remaining > 0) {
    long word;
    long res = sys_ptrace(
        PTRACE_PEEKTEXT, tid, (void *) curr_addr, &word);
    DIE_IF_FMT(res != 0, "PTRACE_PEEKTEXT failed with error %d", res);

    int to_write = remaining > 8 ? 8 : remaining;
    for (int i = 0; i < to_write; i++) {
      word ^= ((long) rc4_get_byte(&rc4)) << (i * 8);
    }

    res = sys_ptrace(PTRACE_POKETEXT, tid, curr_addr, (void *) word);
    DIE_IF_FMT(res < 0, "PTRACE_POKETEXT failed with error %d", res);

    res = sys_ptrace(PTRACE_PEEKTEXT, tid, (void *) curr_addr, &word);
    DIE_IF_FMT(res != 0, "PTRACE_PEEKTEXT failed with error %d", res);

    curr_addr += to_write;
    remaining -= to_write;
  }
}

/* Pulls the third field out of /proc/<pid>/stat, which is a single character
 * representing process state Running, Sleeping, Zombie, etc. */
static char get_thread_state(
    pid_t tid)
{
  /* PROC_STAT_FMT = "/proc/%s/stat" */
  char proc_path[128];
  ks_snprintf(proc_path, sizeof(proc_path), DEOBF_STR(PROC_STAT_FMT), tid);

  int fd =  sys_open(proc_path, O_RDONLY, 0);
  DIE_IF_FMT(fd < 0, "could not open %s error %d", proc_path, fd);

  char buf[4096]; /* Should be enough to hold any /proc/<pid>/stat */
  int ret = sys_read(fd, buf, sizeof(buf) - 1);
  DIE_IF_FMT(ret < 0, "read failed with error %d", ret);
  buf[ret] = '\0';
  sys_close(fd);

  int spaces = 0;
  int i = 0;
  while (spaces != 2) {
    if (buf[i] == ' ')
      spaces++;
    i++;
  }

  return buf[i];
}

void bt_push(struct thread *thread, struct function *fcn)
{
  struct backtrace *new_entry = ks_malloc(sizeof(struct backtrace));
  new_entry->fcn = fcn;
  new_entry->next = thread->bt;
  thread->bt = new_entry;
}

void bt_pop(struct thread *thread)
{
  DIE_IF_FMT(!thread->bt,
      "attempting to pop backtrace item from empty backtrace of tid %d",
      thread->tid);

  struct backtrace *new_bt = thread->bt->next;
  ks_free(thread->bt);
  thread->bt = new_bt;
}

static void stop_threads_in_same_as(
    struct thread *thread,
    struct thread_list *tlist)
{
  struct thread *curr = tlist->head;
  while (curr) {
    if (curr != thread && curr->as == thread->as)
      sys_tgkill(curr->tgid, curr->tid, SIGSTOP);

    /* We need to busy loop here waiting for the SIGSTOP to be delivered since
     * sys_tgkill(pid, SIGSTOP) will not immediately stop the process, there is
     * a period of time between the syscall invocation and when the signal is
     * actually delivered (the signal is said to be pending during this time).
     *
     * To prevent this we must ensure the process is fully stopped before
     * proceeding. We can't do a sys_wait4 on the process as that may return a
     * SIGTRAP event from the process hitting an int3 (which needs to be
     * handled in the main loop in runtime_start). Instead repeatedly poll the
     * third field of /proc/<pid>/stat as to not mess with the ptrace state.
     *
     * Any state other than 'R' is acceptable. 'T' indicates the SIGSTOP has
     * been delivered and all other codes (besides 'R') indicated the process
     * is currently in kernel-space. Upon the next return to userspace, the
     * SIGSTOP will be delivered before any instructions can be executed.
     */
    while (get_thread_state(curr->tid) == 'R') {}

    curr = curr->next;
  }
}

static void handle_fcn_entry(
    struct thread *thread,
    struct trap_point *tp)
{
  DIE_IF(antidebug_proc_check_traced(), TRACED_MSG);
  struct function *fcn = FCN_FROM_TP(tp);

  if (FCN_REFCNT(thread, fcn) == 0) {
    DEBUG_FMT(
        "tid %d: entering encrypted function %s decrypting with key %s",
        thread->tid, fcn->name, STRINGIFY_KEY(&fcn->key));

    rc4_xor_fcn(thread->tid, fcn);
  } else {
    /* This thread hit the trap point for entrance to this function, but an
     * earlier thread decrypted it.
     */
    DEBUG_FMT(
        "tid %d: entering already decrypted function %s",
        thread->tid, fcn->name);
  }

  set_byte_at_addr(thread->tid, tp->addr, tp->value);
  single_step(thread->tid);
  set_byte_at_addr(thread->tid, tp->addr, INT3);

  FCN_ENTER(thread, fcn);
}

static void handle_fcn_exit(
    struct thread *thread,
    struct thread_list *tlist,
    struct trap_point *tp)
{
  DIE_IF(antidebug_proc_check_traced(), TRACED_MSG);

  set_byte_at_addr(thread->tid, tp->addr, tp->value);
  single_step(thread->tid);
  set_byte_at_addr(thread->tid, tp->addr, INT3);

  /* We've now executed the ret or jmp instruction and are in the (potentially)
   * new function. Figure out what it is. */
  struct user_regs_struct regs;
  long res = sys_ptrace(PTRACE_GETREGS, thread->tid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_GETREGS failed with error %d", res);
  struct function *prev_fcn = FCN_FROM_TP(tp);
  struct function *new_fcn = get_fcn_at_addr(regs.ip);

  if (new_fcn != NULL && new_fcn != prev_fcn) {
    /* We've left the function we were previously in for a new one that we
     * have a record of */
    DEBUG_FMT("tid %d: leaving function %s for %s via %s at %p",
              thread->tid, prev_fcn->name, new_fcn->name,
              tp->type == TP_JMP ? "jmp" : "ret", tp->addr);

    FCN_EXIT(thread, prev_fcn);

    /* Encrypt the function we're leaving provided no other thread is in it */
    if (FCN_REFCNT(thread, prev_fcn) == 0) {
      DEBUG_FMT("tid %d: no other threads were executing in %s, encrypting with key %s",
                thread->tid, prev_fcn->name, STRINGIFY_KEY(&new_fcn->key));

      rc4_xor_fcn(thread->tid, prev_fcn);
      set_byte_at_addr(thread->tid, prev_fcn->start_addr, INT3);
    }

    /* If this is a jump to the start instruction of a function, do not execute
     * any of the code under this conditional (decryption if requried and
     * refcount bump will be handled by handle_fcn_entry).
     *
     * If this is a jump to the middle of a function, we're not going to hit
     * the entry trap point for the function, so that work must be done here.
     *
     * This avoids a double encryption/decryption.
     */
    if (tp->type == TP_JMP && new_fcn->start_addr != regs.ip) {
      DEBUG_FMT("tid %d: function %s is being entered via jmp at non start address %p",
                thread->tid, new_fcn->name, regs.ip);
      if (FCN_REFCNT(thread, new_fcn) == 0) {
        DEBUG_FMT("tid %d: function %s being entered is encrypted, decrypting with key %s",
                  thread->tid, new_fcn->name, STRINGIFY_KEY(&new_fcn->key));

        rc4_xor_fcn(thread->tid, new_fcn);
        set_byte_at_addr(thread->tid, new_fcn->start_addr, INT3);
      }

      FCN_ENTER(thread, new_fcn);
    }
  } else if (!new_fcn) {
    /* We've left the function we were previously in for a new one that we
     * don't have a record of. */
    DEBUG_FMT("tid %d: leaving function %s for address %p (no function record) via %s at %p",
              thread->tid, prev_fcn->name, regs.ip,
              tp->type == TP_JMP ? "jmp" : "ret", tp->addr);

    FCN_EXIT(thread, prev_fcn);

    /* Encrypt prev_fcn (function we're leaving) if we were the last one
     * executing in it */
    if (FCN_REFCNT(thread, prev_fcn) == 0) {
      rc4_xor_fcn(thread->tid, prev_fcn);
      set_byte_at_addr(thread->tid, prev_fcn->start_addr, INT3);
    }
  } else {
    /* We've executed an instrumented jmp or ret but remained in the same
     * function */
    DEBUG_FMT("tid %d: hit trap point in %s at %p, but did not leave function (now at %p) (%s)",
              thread->tid, prev_fcn->name, tp->addr, regs.ip,
              tp->type == TP_JMP ? "internal jmp" : "recursive return");

    /* Decrement the refcnt on a recursive return but not an internal jump */
    if (tp->type == TP_RET)
      FCN_EXIT(thread, prev_fcn);
  }
}

static void handle_trap(
    struct thread *thread,
    struct thread_list *tlist,
    int wstatus)
{
  DIE_IF(antidebug_proc_check_traced(), TRACED_MSG);

  long res;
  struct user_regs_struct regs;

  /* Stop all threads in the same address space. Must be done as to not
   * encounter concurrency issues. */
  stop_threads_in_same_as(thread, tlist);

  res = sys_ptrace(PTRACE_GETREGS, thread->tid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_GETREGS failed with error %d", res);

  /* Back up the instruction pointer to the start of the int3 in preparation
   * for executing the original instruction */
  regs.ip--;

  struct trap_point *tp = get_tp(regs.ip);
  if (!tp) {
   DIE_FMT("tid %d: trapped at %p but we don't have an entry",
        thread->tid, regs.ip);
  }

  res = sys_ptrace(PTRACE_SETREGS, thread->tid, NULL, &regs);
  DIE_IF_FMT(res < 0, "PTRACE_SETREGS failed with error %d", res);

  if (tp->type == TP_FCN_ENTRY)
    handle_fcn_entry(thread, tp);
  else
    handle_fcn_exit(thread, tlist, tp);

  DIE_IF(antidebug_signal_check(), TRACED_MSG);

  res = sys_ptrace(PTRACE_CONT, thread->tid, NULL, NULL);
  DIE_IF_FMT(res < 0, "PTRACE_CONT failed with error %d", res);
}

struct thread *find_thread(
    struct thread_list *list,
    pid_t tid)
{
  struct thread *curr = list->head;
  while (curr) {
    if (curr->tid == tid)
      return curr;

    curr = curr->next;
  }

  return NULL;
}

void add_thread(
    struct thread_list *list,
    struct thread *thread)
{
  thread->next = list->head;
  list->head = thread;
  list->size++;
}

void destroy_thread(
    struct thread_list *list,
    struct thread *thread)
{
  DIE_IF(list->head == NULL,
      "(runtime bug) attempting to remove nonexistent thread");

  thread->as->refcnt--;
  if (thread->as->refcnt == 0) {
    ks_free(thread->as->fcn_ref_arr);
    ks_free(thread->as);
  } else {
    /* Thread is exiting, go through its backtrace and decrement function
     * refcounts */
    struct backtrace *curr_bt = thread->bt;
    while (curr_bt) {
      FCN_DEC_REF(thread, curr_bt->fcn);
      if (FCN_REFCNT(thread, curr_bt->fcn) == 0) {
        rc4_xor_fcn(thread->tid, curr_bt->fcn);
        set_byte_at_addr(thread->tid, curr_bt->fcn->start_addr, INT3);
      }
      curr_bt = curr_bt->next;
    }
  }

  /* Free backtrace linked list */
  struct backtrace *curr_bt = thread->bt;
  while (curr_bt) {
    struct backtrace *temp = curr_bt->next;
    ks_free(curr_bt);
    curr_bt = temp;
  }

  struct thread **p = &list->head;
  while ((*p) != thread)
    p = &(*p)->next;

  *p = thread->next;
  list->size--;
  ks_free(thread);
}

struct backtrace *copy_bt(
    struct backtrace *bt)
{
  struct backtrace *copy = NULL;

  struct backtrace *src = bt;
  struct backtrace **dest = &copy;
  while (src) {
    *dest = ks_malloc(sizeof(struct backtrace));
    (*dest)->fcn = src->fcn;

    dest = &(*dest)->next;
    src = src->next;
  }
  *dest = NULL;

  return copy;
}

struct address_space *new_address_space(
    struct address_space *cow_as)
{
    struct address_space *as = ks_malloc(sizeof(struct address_space));
    as->refcnt = 0;

    size_t ref_arr_size = rt_info.nfuncs * sizeof(*as->fcn_ref_arr);
    as->fcn_ref_arr = ks_malloc(ref_arr_size);

    if (cow_as)
      memcpy(as->fcn_ref_arr, cow_as->fcn_ref_arr, ref_arr_size);
    else
      memset(as->fcn_ref_arr, 0, ref_arr_size); /* set everything to encrypted */

    return as;
}

int maybe_handle_new_thread(
    pid_t tid,
    struct thread *orig_thread,
    int wstatus,
    struct thread_list *tlist)
{
  if (!(PTRACE_EVENT_PRESENT(wstatus, PTRACE_EVENT_FORK)  ||
        PTRACE_EVENT_PRESENT(wstatus, PTRACE_EVENT_VFORK) ||
        PTRACE_EVENT_PRESENT(wstatus, PTRACE_EVENT_CLONE))) {
    /* no new thread, do nothing */
    return 0;
  }

  pid_t new_tid;
  long ret = sys_ptrace(PTRACE_GETEVENTMSG, tid, 0, &new_tid);
  DIE_IF_FMT(ret < 0, "PTRACE_GETEVENTMSG failed with error %d", ret);

  /* NB: We don't need to manually set PTRACE_O_TRACECLONE and friends on the
   * new thread here as they'll be inherited from the parent (this is not
   * documented in the ptrace man page).
   */

  DEBUG_FMT("tid %d: new thread created with tid %d", tid, new_tid);

  struct thread *new_thread = ks_malloc(sizeof(struct thread));
  new_thread->tid = new_tid;

  /* Determine if new address space or not */
  struct user_regs_struct regs;
  ret = sys_ptrace(PTRACE_GETREGS, tid, NULL, &regs);
  DIE_IF_FMT(ret < 0, "PTRACE_GETREGS failed with error %d", ret);
  int clone_vm_present = regs.di & CLONE_VM;

  if ((PTRACE_EVENT_PRESENT(wstatus, PTRACE_EVENT_VFORK)) ||
      ((PTRACE_EVENT_PRESENT(wstatus, PTRACE_EVENT_CLONE)) && clone_vm_present)) {
    DEBUG_FMT("tid %d: new thread is executing in same address space", tid);
    new_thread->as = orig_thread->as;
  } else { /* fork syscall, or clone without CLONE_VM, new address space */
    DEBUG_FMT("tid %d: new thread is executing in new address space", tid);
    new_thread->as = new_address_space(orig_thread->as);
  }

  /* Determine what we consider the backtrace of the new thread to be
   *
   * There are two possibilities here, either the thread has done a clone(2)
   * with a child_stack specified as non-null, or done anything else (clone
   * with no child stack, fork, vfork).
   *
   * In the latter of these cases, the logic here is simple. The thread has the
   * same stack and thus the same return addresses on it. The backtrace is
   * therefore identical. Because of this, we just copy the backtrace of the
   * parent thread.
   *
   * The former is a bit trickier. If clone(2) is provided with a child_stack
   * parameter, it must point to a memory region allocated by the parent thread
   * beforehand. Theoretically, this could contain anything, meaning we have no
   * real way of knowing what the backtrace should be. In practice, the clone
   * syscall as implemented in glibc (when returning in the newly-cloned
   * thread), will simply call the passed in fn argument and then immediately
   * exit with its return value. We assume this behaviour here. While this will
   * likely break if a binary does something funky like creating a
   * preformulated stack and passing that in as child_stack, we have no way of
   * handling all such funky cases and assuming the glibc behaviour should
   * cover 99.99% of cases involving clone(2).
   */
  void *child_stack = (void *) regs.si;
  if (((PTRACE_EVENT_PRESENT(wstatus, PTRACE_EVENT_CLONE)) && child_stack != NULL)) {
    DEBUG_FMT("tid %d: new thread has a new stack, removing backtrace", tid);
    /* Backtrace initially contains just the function the thread was in
     * (eg. __clone for glibc) */
    new_thread->bt = NULL;
    if (orig_thread->bt)
      FCN_ENTER(new_thread, orig_thread->bt->fcn);
  } else {
    DEBUG_FMT("tid %d: new thread has the same stack, copying backtrace", tid);
    new_thread->bt = copy_bt(orig_thread->bt);
  }

  if (regs.di & CLONE_THREAD) {
    /* New thread group, new_thread is thread group leader */
    new_thread->tgid = tid;
  } else {
    new_thread->tgid = orig_thread->tgid;
  }

  new_thread->as->refcnt++;
  new_thread->has_wait_prio = 0;
  add_thread(tlist, new_thread);

  /* Both the existing and new thread will be stopped */
  ret = sys_ptrace(PTRACE_CONT, tid, 0, 0);
  DIE_IF_FMT(ret < 0, "PTRACE_CONT failed with error %d", ret);

retry_child_wait:
  /* The child may not have been scheduled yet, in which case
   * ptrace(PTRACE_CONT, ...) will fail with -ESRCH, loop until it succeeds to
   * get around this.
   */
  ret = sys_ptrace(PTRACE_CONT, new_tid, 0, 0);
  DIE_IF_FMT(ret < 0 && ret != -ESRCH, "PTRACE_CONT failed with error %d", ret);

  if (ret == -ESRCH)
    goto retry_child_wait;

  return 1;
}

/* Fairly waits on all threads in the packed program.
 *
 * This is a wrapper for sys_wait4 used in the main runtime loop to wait
 * on the next thread to service for function encryption or decryption. It gets
 * around a subtle ptrace timing issue.
 *
 * The wait4 syscall is not fair in the sense that a thread rapidly changing
 * state can monopolise it and cause other threads to not be waited on.
 * Internally, when a process ptraces a new thread, it's task_struct is added
 * to a linked list of traced threads in tracer_task_struct->ptraced. New
 * threads are pushed onto the head of this linked list. Whenever the tracer
 * does a wait4, this list is iterated head to tail, with the first thread
 * exhibiting a changed state being the thread that is waited on.
 *
 * This has the consequence that, if the threads at the head of the list very
 * rapidly change state, threads further down in the list may need to wait a
 * very long time, or even forever to get serviced if there are enough threads
 * in front of them changing state rapidly enough. In the case of Kiteshield,
 * this will cause the threads further down in the list to wait a long time or
 * potentially forever for function encryption/decryption. Both of these
 * behaviors (program slowness and program lockup) have been observed when this
 * helper was not in use.
 *
 * To get around this, we wait on threads in a round-robin fashion. The list of
 * threads in the packed program is iterated and each one is waited on with
 * WNOHANG. If the thread has not changed state, we continue on to the next,
 * wrapping around to the head of the list and repeating until we find a thread
 * that has changed state. The next thread to be waited on is preserved via the
 * has_wait_prio flag to preserve strict round-robin ordering between calls.
 */
pid_t fair_wait_threads(struct thread_list *tlist, int *wstatus)
{
  struct thread *curr = tlist->head;
  while (curr) {
    if (curr->has_wait_prio)
      break;
    curr = curr->next;
  }

  /* If curr == NULL, the thread with wait priority was just destroyed. Just
     give wait priority to the head of the list. */
  if (curr == NULL) {
    curr = tlist->head;
  }
  curr->has_wait_prio = 0;

  pid_t tid;
  while (1) {
    tid = sys_wait4(curr->tid, wstatus, __WALL | WNOHANG);
    DIE_IF_FMT(tid < 0, "wait4 syscall failed with error %d", tid);

    /* Return value of 0 indicates thread has not changed state */
    if (tid != 0)
      break;

    if (curr->next)
      curr = curr->next;
    else
      curr = tlist->head;
  }

  if (curr->next)
    curr->next->has_wait_prio = 1;
  else
    tlist->head->has_wait_prio = 1;

  return tid;
}

void setup_initial_thread(pid_t tid, struct thread_list *tlist)
{
  /* Set up state for initial forked child (special case of
   * maybe_handle_new_thread).
   */
  long ret;
  while (1) {
    /* Spin while we wait for the child do do a ptrace(PTRACE_TRACEME, ...) and
     * then a raise(SIGSTOP). */
    ret = sys_ptrace(PTRACE_SETOPTIONS, tid, 0,
        (void *) (PTRACE_O_EXITKILL   |
                  PTRACE_O_TRACECLONE |
                  PTRACE_O_TRACEFORK  |
                  PTRACE_O_TRACEEXIT  |
                  PTRACE_O_TRACEVFORK));
    DIE_IF_FMT(ret < 0 && ret != -ESRCH,
        "PTRACE_SETOPTIONS failed with error %d", ret);

    if (ret == 0) break;
  }

  struct thread *thread = ks_malloc(sizeof(struct thread));
  thread->has_wait_prio = 1;
  thread->tgid = tid; /* Created via fork so it's the thread group leader */
  thread->tid = tid;
  thread->as = new_address_space(NULL);
  thread->as->refcnt = 1;
  thread->bt = NULL;
  thread->next = NULL;
  add_thread(tlist, thread);

  ret = sys_ptrace(PTRACE_CONT, tid, 0, 0);
  DIE_IF_FMT(ret < 0, "PTRACE_CONT failed with error %d", ret);
}

static void handle_thread_exit(
    struct thread *thread,
    struct thread_list *tlist)
{
  /* Undocumented Linux magic right here.
   *
   * If the thread group leader of a thread group with > 1 thread exits
   * while being ptraced, it will hang around as a zombie. Attempting to
   * sys_wait4 on it will result in infinite hanging. It can only be
   * successfully wait4'ed on when every other thread in the thread group
   * has exited and been reaped. This behavior is not documented in the
   * ptrace manpage.
   *
   * Due to this, we don't wait4 on threads if they're the thread group
   * leader. We just let them hang around as zombies until the runtime
   * exits and they're automatically reaped thanks to PTRACE_O_EXITKILL.
   */
  int needs_wait = thread->tgid != thread->tid;
  pid_t tid = thread->tid;

  destroy_thread(tlist, thread);
  /* thread is now freed */

  /* Continue thread and catch exit event */
  long err = sys_ptrace(PTRACE_CONT, tid, NULL, NULL);
  DIE_IF_FMT(err < 0, "PTRACE_CONT failed with error %d", err);

  if (needs_wait) {
    int wstatus;
    tid = sys_wait4(tid, &wstatus, __WALL);
    DIE_IF_FMT(tid < 0, "wait4 syscall failed with error %d", tid);

    DIE_IF_FMT(!WIFEXITED(wstatus), "tid %d expected to exit but did not",
        tid);
    DEBUG_FMT("tid %d: exited with status %d", tid, WEXITSTATUS(wstatus));
  } else {
    DEBUG_FMT(
        "tid %d: exited but will remain a zombie due to being tg leader",
        tid);
  }
}

void runtime_start(pid_t child_pid)
{
  DEBUG("starting ptrace runtime");
  obf_deobf_rt_info(&rt_info);

  DEBUG_FMT("number of trap points: %u", rt_info.ntraps);
  DEBUG_FMT("number of encrypted functions: %u", rt_info.nfuncs);

  antidebug_signal_init();

#ifdef DEBUG_OUTPUT
  DEBUG("list of trap points:");
  for (int i = 0; i < rt_info.ntraps; i++) {
    struct trap_point *tp = ((struct trap_point *) rt_info.data) + i;
    const char *type =
      tp->type == TP_JMP ? "jmp" : tp->type == TP_RET ? "ret" : "ent";
    DEBUG_FMT("%p value: %hhx, type: %s, function: %s (#%d)",
              tp->addr, tp->value, type,
              FCN_FROM_TP(tp)->name, FCN_FROM_TP(tp)->id);
  }
#endif

  ks_malloc_init();

  /* debugger checks are scattered throughout the runtime to interfere with
   * debugger attaches as much as possible.
   */
  DIE_IF(antidebug_proc_check_traced(), TRACED_MSG);

  /* Do the prctl down here so a reverse engineer will have to defeat the
   * preceeding antidebug_proc_check_traced() call before prctl shows up in a
   * strace */
  antidebug_prctl_set_nondumpable();

  struct thread_list tlist;
  tlist.size = 0;
  tlist.head = NULL;

  setup_initial_thread(child_pid, &tlist);

  /* Main runtime loop */
  while (1) {
    int wstatus;
    pid_t pid = fair_wait_threads(&tlist, &wstatus);

    struct thread *thread = find_thread(&tlist, pid);
    DIE_IF_FMT(!thread,
        "(runtime bug) tid %d trapped but we don't have a record of it", pid);

    if (maybe_handle_new_thread(pid, thread, wstatus, &tlist))
      continue; /* Stopped because of a new thread, not a function entry/exit*/

    /* destroy_thread (which is called by handle_thread_exit) requires that the
     * thread not yet have exited as it may need to re-encrypt functions in the
     * thread's address space if there are now no threads executing in them. We
     * thus we use PTRACE_EVENT_EXIT instead of WIFEXITED here to keep the
     * thread in a "just about to exit" state that will allow the use of
     * PTRACE_[PEEK/POKE]TEXT.
     */
    if (PTRACE_EVENT_PRESENT(wstatus, PTRACE_EVENT_EXIT)) {
      handle_thread_exit(thread, &tlist);

      if (tlist.size == 0) {
        DEBUG("all threads exited, exiting");
        sys_exit(0);
      }
      continue;
    }

    DIE_IF_FMT(
        WIFSIGNALED(wstatus),
        "child was killed by signal, %u exiting", WTERMSIG(wstatus));
    DIE_IF(
        !WIFSTOPPED(wstatus),
        "child was stopped unexpectedly, exiting");

    if (WSTOPSIG(wstatus) != SIGTRAP && WSTOPSIG(wstatus) != SIGSTOP) {
      DEBUG_FMT("child %d was sent non-SIGTRAP signal %u",
          pid, WSTOPSIG(wstatus));

      /* Forward signal to child and continue */
      sys_ptrace(PTRACE_CONT, pid, NULL, (void *) (long) WSTOPSIG(wstatus));
      continue;
    }

    if (WSTOPSIG(wstatus) == SIGSTOP) {
      /* Thread stopped by runtime for function decryption or encryption,
       * PTRACE_CONT and continue */
      sys_ptrace(PTRACE_CONT, pid, NULL, NULL);
      continue;
    }

    DIE_IF(antidebug_proc_check_traced(), TRACED_MSG);
    DIE_IF(antidebug_signal_check(), TRACED_MSG);

    handle_trap(thread, &tlist, wstatus);
  }
}

void do_fork()
{
  DIE_IF(antidebug_proc_check_traced(), TRACED_MSG);

  long ret;
  pid_t pid = sys_fork();
  DIE_IF_FMT(pid < 0, "fork failed with error %d", pid);

  if (pid != 0) {
    runtime_start(pid);
    sys_exit(0); /* Only the child returns from do_fork */
  }

  /* Just in case the earlier one in load() was patched out :) */
  antidebug_rlimit_set_zero_core();

  ret = sys_ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  DIE_IF_FMT(ret < 0, "child: PTRACE_TRACEME failed with error %d", ret);

  /* Pause here so runtime can init itself, runtime will do PTRACE_CONT when
   * ready
   */
  sys_kill(sys_getpid(), SIGSTOP);

  DEBUG("child is traced, handing control to packed binary");
}

#endif /* USE_RUNTIME */
