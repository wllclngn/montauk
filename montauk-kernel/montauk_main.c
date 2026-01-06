// SPDX-License-Identifier: GPL-2.0
/*
 * montauk_main.c - Main module entry/exit for montauk kernel module
 *
 * Copyright (C) 2025
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/time64.h>
#include <asm/param.h>

#include "montauk.h"

/* Module metadata */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("montauk developers");
MODULE_DESCRIPTION("Process telemetry for montauk system monitor");
MODULE_VERSION("0.1.0");

/* Global state */
struct rhashtable montauk_proc_table;
struct montauk_stats montauk_stats;

/* Module parameters */
int montauk_max_procs = MONTAUK_DEFAULT_MAX_PROCS;
module_param_named(max_procs, montauk_max_procs, int, 0444);
MODULE_PARM_DESC(max_procs, "Maximum number of processes to track (default: 8192)");

bool montauk_debug = false;
module_param_named(debug, montauk_debug, bool, 0644);
MODULE_PARM_DESC(debug, "Enable debug logging (default: false)");

/* Refresh interval in jiffies (1 second) */
#define MONTAUK_REFRESH_INTERVAL HZ

/* Delayed work for periodic refresh */
static struct delayed_work montauk_refresh_work;
static bool refresh_running = false;

/* Convert nanoseconds to clock ticks (USER_HZ) */
static inline u64 montauk_nsec_to_ticks(u64 nsec)
{
    return div_u64(nsec, NSEC_PER_SEC / USER_HZ);
}

/*
 * Refresh CPU times for a single process
 * Called from workqueue context (can sleep)
 */
static void montauk_refresh_proc_times(struct montauk_proc *proc)
{
    struct task_struct *task;
    struct pid *pid_struct;
    struct mm_struct *mm;

    pid_struct = find_get_pid(proc->pid);
    if (!pid_struct)
        return;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);

    if (!task)
        return;

    /* Update CPU times */
    proc->utime = montauk_nsec_to_ticks(task->utime);
    proc->stime = montauk_nsec_to_ticks(task->stime);

    /* Update state */
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
        break;
    }

    /* Update thread count */
    if (thread_group_leader(task) && task->signal)
        proc->nr_threads = get_nr_threads(task);

    /* Update RSS - can do this here since we're in process context */
    mm = get_task_mm(task);
    if (mm) {
        proc->rss_pages = get_mm_rss(mm);
        mmput(mm);
    }

    put_task_struct(task);
}

/*
 * Worker function: refresh all tracked processes
 * Runs every MONTAUK_REFRESH_INTERVAL (1 second)
 */
static void montauk_refresh_worker(struct work_struct *work)
{
    struct rhashtable_iter iter;
    struct montauk_proc *proc;

    rhashtable_walk_enter(&montauk_proc_table, &iter);
    rhashtable_walk_start(&iter);

    while ((proc = rhashtable_walk_next(&iter)) != NULL) {
        if (IS_ERR(proc))
            continue;
        montauk_refresh_proc_times(proc);
    }

    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

    /* Reschedule if still running */
    if (refresh_running)
        schedule_delayed_work(&montauk_refresh_work, MONTAUK_REFRESH_INTERVAL);
}

/* Start the refresh worker */
static void montauk_refresh_start(void)
{
    refresh_running = true;
    INIT_DELAYED_WORK(&montauk_refresh_work, montauk_refresh_worker);
    schedule_delayed_work(&montauk_refresh_work, MONTAUK_REFRESH_INTERVAL);
    montauk_dbg("refresh worker started (interval=%dms)\n", 1000 * MONTAUK_REFRESH_INTERVAL / HZ);
}

/* Stop the refresh worker */
static void montauk_refresh_stop(void)
{
    refresh_running = false;
    cancel_delayed_work_sync(&montauk_refresh_work);
    montauk_dbg("refresh worker stopped\n");
}

static int __init montauk_init(void)
{
    int ret;

    montauk_info("initializing (max_procs=%d, debug=%d)\n",
                 montauk_max_procs, montauk_debug);

    /* Initialize statistics */
    atomic_set(&montauk_stats.tracked, 0);
    atomic64_set(&montauk_stats.forks, 0);
    atomic64_set(&montauk_stats.execs, 0);
    atomic64_set(&montauk_stats.exits, 0);
    atomic64_set(&montauk_stats.overflows, 0);
    montauk_stats.load_time = ktime_get_boottime();

    /* Initialize process table */
    ret = montauk_table_init();
    if (ret) {
        montauk_err("failed to initialize process table: %d\n", ret);
        return ret;
    }

    /* Register kprobe hooks */
    ret = montauk_hooks_register();
    if (ret) {
        montauk_err("failed to register kprobe hooks: %d\n", ret);
        goto err_table;
    }

    /* Populate table with existing processes */
    montauk_populate_existing();

    /* Start periodic refresh worker */
    montauk_refresh_start();

    /* Register genetlink interface */
    ret = montauk_netlink_init();
    if (ret) {
        montauk_err("failed to register genetlink family: %d\n", ret);
        goto err_refresh;
    }

    montauk_info("loaded successfully (tracking %d processes)\n",
                 atomic_read(&montauk_stats.tracked));

    return 0;

err_refresh:
    montauk_refresh_stop();
    montauk_hooks_unregister();
err_table:
    montauk_table_destroy();
    return ret;
}

static void __exit montauk_exit(void)
{
    u64 uptime_sec;

    uptime_sec = ktime_divns(ktime_sub(ktime_get_boottime(),
                                       montauk_stats.load_time),
                             NSEC_PER_SEC);

    montauk_info("unloading (uptime=%llus, forks=%lld, execs=%lld, exits=%lld)\n",
                 uptime_sec,
                 atomic64_read(&montauk_stats.forks),
                 atomic64_read(&montauk_stats.execs),
                 atomic64_read(&montauk_stats.exits));

    /* Unregister genetlink interface */
    montauk_netlink_exit();

    /* Stop refresh worker */
    montauk_refresh_stop();

    /* Unregister kprobe hooks */
    montauk_hooks_unregister();

    /* Destroy process table */
    montauk_table_destroy();

    montauk_info("unloaded\n");
}

module_init(montauk_init);
module_exit(montauk_exit);
