/* SPDX-License-Identifier: GPL-2.0 */
/*
 * montauk.h - Shared definitions for montauk kernel module
 *
 * Copyright (C) 2025
 */

#ifndef _MONTAUK_H
#define _MONTAUK_H

#include <linux/types.h>

/* Genetlink family name and version */
#define MONTAUK_GENL_NAME       "MONTAUK"
#define MONTAUK_GENL_VERSION    1

/* Genetlink multicast group (for future SUBSCRIBE) */
#define MONTAUK_MCGRP_EVENTS    "events"

/* Genetlink commands */
enum montauk_cmd {
    MONTAUK_CMD_UNSPEC = 0,
    MONTAUK_CMD_GET_SNAPSHOT,   /* Dump all processes */
    MONTAUK_CMD_GET_STATS,      /* Get module statistics */
    __MONTAUK_CMD_MAX,
};
#define MONTAUK_CMD_MAX (__MONTAUK_CMD_MAX - 1)

/* Genetlink attributes */
enum montauk_attr {
    MONTAUK_ATTR_UNSPEC = 0,
    MONTAUK_ATTR_PID,           /* u32: Process ID */
    MONTAUK_ATTR_PPID,          /* u32: Parent process ID */
    MONTAUK_ATTR_COMM,          /* string: Command name (max 16 chars) */
    MONTAUK_ATTR_STATE,         /* u8: Process state (R/S/D/Z/T) */
    MONTAUK_ATTR_UTIME,         /* u64: User CPU time (clock ticks) */
    MONTAUK_ATTR_STIME,         /* u64: System CPU time (clock ticks) */
    MONTAUK_ATTR_RSS_PAGES,     /* u64: Resident set size (pages) */
    MONTAUK_ATTR_UID,           /* u32: User ID */
    MONTAUK_ATTR_THREADS,       /* u32: Thread count */
    MONTAUK_ATTR_EXE_PATH,      /* string: Executable path */
    MONTAUK_ATTR_START_TIME,    /* u64: Process start time (ns since boot) */
    MONTAUK_ATTR_CMDLINE,       /* string: Full command line with arguments */
    MONTAUK_ATTR_PROC_ENTRY,    /* nested: Container for process attributes */
    MONTAUK_ATTR_PROC_COUNT,    /* u32: Total process count in snapshot */

    /* Statistics attributes (for GET_STATS) */
    MONTAUK_ATTR_STAT_TRACKED,      /* u32: Currently tracked processes */
    MONTAUK_ATTR_STAT_FORKS,        /* u64: Total fork events since load */
    MONTAUK_ATTR_STAT_EXECS,        /* u64: Total exec events */
    MONTAUK_ATTR_STAT_EXITS,        /* u64: Total exit events */
    MONTAUK_ATTR_STAT_OVERFLOWS,    /* u64: Times max_procs limit hit */
    MONTAUK_ATTR_STAT_UPTIME_SEC,   /* u64: Seconds since module load */

    __MONTAUK_ATTR_MAX,
};
#define MONTAUK_ATTR_MAX (__MONTAUK_ATTR_MAX - 1)

/* Maximum lengths */
#define MONTAUK_COMM_LEN        16
#define MONTAUK_EXE_PATH_LEN    256
#define MONTAUK_CMDLINE_LEN     256

/* Default module parameters */
#define MONTAUK_DEFAULT_MAX_PROCS   8192

#ifdef __KERNEL__

#include <linux/rhashtable.h>
#include <linux/refcount.h>
#include <linux/rcupdate.h>

/*
 * struct montauk_proc - Per-process tracking entry
 *
 * Stored in an rhashtable keyed by PID. Updated on fork/exec/exit
 * via kprobes. Read via RCU during snapshot export.
 */
struct montauk_proc {
    struct rhash_head   node;       /* Hash table linkage */
    refcount_t          refcnt;     /* Reference count */
    struct rcu_head     rcu;        /* RCU callback head */

    /* Process identity */
    pid_t               pid;
    pid_t               ppid;
    char                comm[MONTAUK_COMM_LEN];

    /* Resource usage (refreshed on snapshot request) */
    u64                 utime;
    u64                 stime;
    u64                 start_time;
    unsigned long       rss_pages;

    /* State */
    char                state;
    uid_t               uid;
    int                 nr_threads;

    /* Executable path (cached on exec) */
    char                exe_path[MONTAUK_EXE_PATH_LEN];
};

/* Module statistics */
struct montauk_stats {
    atomic_t            tracked;        /* Current tracked count */
    atomic64_t          forks;          /* Total fork events */
    atomic64_t          execs;          /* Total exec events */
    atomic64_t          exits;          /* Total exit events */
    atomic64_t          overflows;      /* Times limit was hit */
    ktime_t             load_time;      /* Module load timestamp */
};

/* Global module state (defined in montauk_main.c) */
extern struct rhashtable montauk_proc_table;
extern struct montauk_stats montauk_stats;
extern int montauk_max_procs;
extern bool montauk_debug;

/* Table operations (montauk_table.c) */
int montauk_table_init(void);
void montauk_table_destroy(void);
struct montauk_proc *montauk_proc_alloc(pid_t pid);
void montauk_proc_free(struct montauk_proc *proc);
int montauk_proc_insert(struct montauk_proc *proc);
struct montauk_proc *montauk_proc_lookup(pid_t pid);
void montauk_proc_remove(pid_t pid);
void montauk_proc_update_from_task(struct montauk_proc *proc,
                                   struct task_struct *task);

/* Kprobe hooks (montauk_hooks.c) */
int montauk_hooks_register(void);
void montauk_hooks_unregister(void);
void montauk_populate_existing(void);

/* Netlink interface (montauk_netlink.c) */
int montauk_netlink_init(void);
void montauk_netlink_exit(void);

/* Debug logging */
#define montauk_dbg(fmt, ...) \
    do { if (montauk_debug) pr_debug("montauk: " fmt, ##__VA_ARGS__); } while (0)

#define montauk_info(fmt, ...) \
    pr_info("montauk: " fmt, ##__VA_ARGS__)

#define montauk_err(fmt, ...) \
    pr_err("montauk: " fmt, ##__VA_ARGS__)

#endif /* __KERNEL__ */

#endif /* _MONTAUK_H */
