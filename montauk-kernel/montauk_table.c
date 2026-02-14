// SPDX-License-Identifier: GPL-2.0
/*
 * montauk_table.c - Process table management using rhashtable
 *
 * Copyright (C) 2025
 */

#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/time64.h>
#include <asm/param.h>

#include "montauk.h"

/* Convert nanoseconds to clock ticks (USER_HZ) - nsec_to_clock_t not exported */
static inline u64 montauk_nsec_to_ticks(u64 nsec)
{
    return div_u64(nsec, NSEC_PER_SEC / USER_HZ);
}

/* Hash table key is the PID */
static u32 montauk_proc_hash(const void *data, u32 len, u32 seed)
{
    const struct montauk_proc *proc = data;
    return jhash_1word(proc->pid, seed);
}

static u32 montauk_proc_key_hash(const void *key, u32 len, u32 seed)
{
    pid_t pid = *(const pid_t *)key;
    return jhash_1word(pid, seed);
}

static int montauk_proc_cmp(struct rhashtable_compare_arg *arg,
                            const void *obj)
{
    const struct montauk_proc *proc = obj;
    pid_t pid = *(const pid_t *)arg->key;
    return proc->pid != pid;
}

static const struct rhashtable_params montauk_proc_params = {
    .key_len        = sizeof(pid_t),
    .key_offset     = offsetof(struct montauk_proc, pid),
    .head_offset    = offsetof(struct montauk_proc, node),
    .hashfn         = montauk_proc_key_hash,
    .obj_hashfn     = montauk_proc_hash,
    .obj_cmpfn      = montauk_proc_cmp,
    .automatic_shrinking = true,
};

/* Initialize the process table */
int montauk_table_init(void)
{
    return rhashtable_init(&montauk_proc_table, &montauk_proc_params);
}

/* RCU callback to free a process entry */
static void montauk_proc_free_rcu(struct rcu_head *head)
{
    struct montauk_proc *proc = container_of(head, struct montauk_proc, rcu);
    kfree(proc);
}

/* Destroy the process table and free all entries */
void montauk_table_destroy(void)
{
    struct rhashtable_iter iter;
    struct montauk_proc *proc;

    rhashtable_walk_enter(&montauk_proc_table, &iter);
    rhashtable_walk_start(&iter);

    while ((proc = rhashtable_walk_next(&iter)) != NULL) {
        if (IS_ERR(proc))
            continue;
        rhashtable_remove_fast(&montauk_proc_table, &proc->node,
                               montauk_proc_params);
        kfree(proc);
    }

    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);
    rhashtable_destroy(&montauk_proc_table);
}

/* Allocate a new process entry */
struct montauk_proc *montauk_proc_alloc(pid_t pid)
{
    struct montauk_proc *proc;

    /* Check limit */
    if (atomic_read(&montauk_stats.tracked) >= montauk_max_procs) {
        atomic64_inc(&montauk_stats.overflows);
        montauk_dbg("max_procs limit reached (%d)\n", montauk_max_procs);
        return NULL;
    }

    proc = kzalloc(sizeof(*proc), GFP_ATOMIC);
    if (!proc)
        return NULL;

    proc->pid = pid;
    refcount_set(&proc->refcnt, 1);

    return proc;
}

/* Free a process entry (via RCU) */
void montauk_proc_free(struct montauk_proc *proc)
{
    if (proc)
        call_rcu(&proc->rcu, montauk_proc_free_rcu);
}

/* Insert a process entry into the table */
int montauk_proc_insert(struct montauk_proc *proc)
{
    int ret;

    ret = rhashtable_insert_fast(&montauk_proc_table, &proc->node,
                                 montauk_proc_params);
    if (ret == 0)
        atomic_inc(&montauk_stats.tracked);

    return ret;
}

/* Lookup a process entry by PID (caller must hold RCU read lock) */
struct montauk_proc *montauk_proc_lookup(pid_t pid)
{
    return rhashtable_lookup_fast(&montauk_proc_table, &pid,
                                  montauk_proc_params);
}

/* Remove a process entry by PID */
void montauk_proc_remove(pid_t pid)
{
    struct montauk_proc *proc;

    rcu_read_lock();
    proc = montauk_proc_lookup(pid);
    if (proc) {
        if (rhashtable_remove_fast(&montauk_proc_table, &proc->node,
                                   montauk_proc_params) == 0) {
            atomic_dec(&montauk_stats.tracked);
            montauk_proc_free(proc);
        }
    }
    rcu_read_unlock();
}

/*
 * Update a process entry from task_struct
 * Called during snapshot to refresh dynamic fields
 */
void montauk_proc_update_from_task(struct montauk_proc *proc,
                                   struct task_struct *task)
{
    struct mm_struct *mm;
    struct file *exe_file;
    char *path_buf;
    char *path;

    if (!task)
        return;

    /* Basic fields from task_struct */
    proc->ppid = task_pid_nr(task->real_parent);
    memcpy(proc->comm, task->comm, TASK_COMM_LEN);
    proc->comm[TASK_COMM_LEN - 1] = '\0';

    /* CPU times - convert from nanoseconds to clock ticks (USER_HZ) */
    proc->utime = montauk_nsec_to_ticks(task->utime);
    proc->stime = montauk_nsec_to_ticks(task->stime);
    proc->start_time = montauk_nsec_to_ticks(task->start_boottime);

    /* Process state */
    switch (READ_ONCE(task->__state)) {
    case TASK_RUNNING:
        proc->state = 'R';
        break;
    case TASK_INTERRUPTIBLE:
        proc->state = 'S';
        break;
    case TASK_UNINTERRUPTIBLE:
        proc->state = 'D';
        break;
    case __TASK_STOPPED:
        proc->state = 'T';
        break;
    default:
        if (task->exit_state == EXIT_ZOMBIE)
            proc->state = 'Z';
        else
            proc->state = '?';
        break;
    }

    /* User ID */
    proc->uid = from_kuid_munged(current_user_ns(), task_uid(task));

    /* Thread count (for thread group leader) */
    if (thread_group_leader(task) && task->signal)
        proc->nr_threads = get_nr_threads(task);
    else
        proc->nr_threads = 1;

    /* RSS - need mm_struct */
    mm = get_task_mm(task);
    if (mm) {
        proc->rss_pages = get_mm_rss(mm);
        mmput(mm);
    } else {
        proc->rss_pages = 0;
    }

    /* Executable path - access exe_file directly since get_mm_exe_file not exported */
    mm = get_task_mm(task);
    if (mm) {
        rcu_read_lock();
        exe_file = get_file_rcu(&mm->exe_file);
        if (exe_file) {
            path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
            if (path_buf) {
                path = d_path(&exe_file->f_path, path_buf, PATH_MAX);
                if (!IS_ERR(path)) {
                    strscpy(proc->exe_path, path, MONTAUK_EXE_PATH_LEN);
                }
                kfree(path_buf);
            }
            fput(exe_file);
        }
        rcu_read_unlock();
        mmput(mm);
    }

}
