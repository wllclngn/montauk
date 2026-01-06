// SPDX-License-Identifier: GPL-2.0
/*
 * montauk_hooks.c - Kprobe handlers for process lifecycle events
 *
 * Uses kprobes instead of tracepoints since scheduler tracepoints
 * aren't exported for out-of-tree modules.
 *
 * Copyright (C) 2025
 */

#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm_types.h>
#include <linux/cred.h>

#include "montauk.h"

/* Convert nanoseconds to clock ticks (USER_HZ) */
static inline u64 montauk_nsec_to_ticks(u64 nsec)
{
    return div_u64(nsec, NSEC_PER_SEC / USER_HZ);
}

/*
 * Lightweight init for kprobe context (atomic, cannot sleep)
 * Only copies fields that don't require sleeping operations
 */
static void montauk_proc_init_atomic(struct montauk_proc *proc,
                                     struct task_struct *task)
{
    proc->ppid = task_pid_nr(task->real_parent);
    memcpy(proc->comm, task->comm, TASK_COMM_LEN);
    proc->comm[TASK_COMM_LEN - 1] = '\0';
    proc->utime = montauk_nsec_to_ticks(task->utime);
    proc->stime = montauk_nsec_to_ticks(task->stime);
    proc->start_time = montauk_nsec_to_ticks(task->start_boottime);
    proc->state = 'R';  /* New processes start running */
    proc->uid = from_kuid_munged(&init_user_ns, task_uid(task));
    proc->nr_threads = 1;
    proc->rss_pages = 0;
    proc->exe_path[0] = '\0';
    proc->cmdline[0] = '\0';
}

/*
 * Kprobe handler: wake_up_new_task
 * Called when a newly forked task is about to be scheduled.
 * Signature: void wake_up_new_task(struct task_struct *p)
 */
static int montauk_fork_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct task_struct *child;
    struct montauk_proc *proc;
    pid_t pid;

    /* First argument is the new task */
#ifdef CONFIG_X86_64
    child = (struct task_struct *)regs->di;
#elif defined(CONFIG_ARM64)
    child = (struct task_struct *)regs->regs[0];
#else
    return 0;  /* Unsupported arch */
#endif

    if (!child)
        return 0;

    /* Only track thread group leaders (processes, not threads) */
    if (!thread_group_leader(child))
        return 0;

    pid = task_pid_nr(child);

    montauk_dbg("fork: pid=%d comm=%s\n", pid, child->comm);

    proc = montauk_proc_alloc(pid);
    if (!proc)
        return 0;

    /* Initialize with atomic-safe fields only (kprobe context cannot sleep) */
    montauk_proc_init_atomic(proc, child);

    if (montauk_proc_insert(proc) != 0) {
        /* Already exists or insert failed */
        kfree(proc);
        return 0;
    }

    atomic64_inc(&montauk_stats.forks);
    return 0;
}

/*
 * Kprobe handler: begin_new_exec
 * Called during execve after the new executable is set up.
 * Signature: int begin_new_exec(struct linux_binprm *bprm)
 */
static int montauk_exec_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct task_struct *task = current;
    struct montauk_proc *proc;
    pid_t pid = task_pid_nr(task);

    montauk_dbg("exec: pid=%d comm=%s\n", pid, task->comm);

    rcu_read_lock();
    proc = montauk_proc_lookup(pid);
    if (proc) {
        /* Update comm after exec */
        memcpy(proc->comm, task->comm, TASK_COMM_LEN);
        proc->comm[TASK_COMM_LEN - 1] = '\0';

        /* exe_path will be updated on next snapshot */
        proc->exe_path[0] = '\0';
    }
    rcu_read_unlock();

    atomic64_inc(&montauk_stats.execs);
    return 0;
}

/*
 * Kprobe handler: do_exit
 * Called when a process terminates.
 * Signature: void __noreturn do_exit(long code)
 */
static int montauk_exit_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct task_struct *task = current;
    pid_t pid;

    /* Only handle thread group leaders */
    if (!thread_group_leader(task))
        return 0;

    pid = task_pid_nr(task);

    montauk_dbg("exit: pid=%d comm=%s\n", pid, task->comm);

    montauk_proc_remove(pid);

    atomic64_inc(&montauk_stats.exits);
    return 0;
}

/* Kprobe structures */
static struct kprobe kp_fork = {
    .symbol_name = "wake_up_new_task",
    .pre_handler = montauk_fork_handler,
};

static struct kprobe kp_exec = {
    .symbol_name = "begin_new_exec",
    .pre_handler = montauk_exec_handler,
};

static struct kprobe kp_exit = {
    .symbol_name = "do_exit",
    .pre_handler = montauk_exit_handler,
};

/* Registration state */
static bool hooks_registered = false;

/*
 * Register all kprobe hooks
 */
int montauk_hooks_register(void)
{
    int ret;

    ret = register_kprobe(&kp_fork);
    if (ret < 0) {
        montauk_err("failed to register fork kprobe: %d\n", ret);
        return ret;
    }

    ret = register_kprobe(&kp_exec);
    if (ret < 0) {
        montauk_err("failed to register exec kprobe: %d\n", ret);
        goto err_fork;
    }

    ret = register_kprobe(&kp_exit);
    if (ret < 0) {
        montauk_err("failed to register exit kprobe: %d\n", ret);
        goto err_exec;
    }

    hooks_registered = true;
    montauk_info("kprobe hooks registered\n");
    return 0;

err_exec:
    unregister_kprobe(&kp_exec);
err_fork:
    unregister_kprobe(&kp_fork);
    return ret;
}

/*
 * Unregister all kprobe hooks
 */
void montauk_hooks_unregister(void)
{
    if (!hooks_registered)
        return;

    unregister_kprobe(&kp_exit);
    unregister_kprobe(&kp_exec);
    unregister_kprobe(&kp_fork);

    hooks_registered = false;
    montauk_info("kprobe hooks unregistered\n");
}

/*
 * Populate the table with all existing processes
 * Called during module initialization
 */
void montauk_populate_existing(void)
{
    struct task_struct *task;
    struct montauk_proc *proc;
    int count = 0;

    rcu_read_lock();
    for_each_process(task) {
        if (!thread_group_leader(task))
            continue;

        proc = montauk_proc_alloc(task_pid_nr(task));
        if (!proc)
            continue;

        montauk_proc_update_from_task(proc, task);

        if (montauk_proc_insert(proc) == 0) {
            count++;
        } else {
            kfree(proc);
        }
    }
    rcu_read_unlock();

    montauk_dbg("populated %d existing processes\n", count);
}
