// SPDX-License-Identifier: GPL-2.0
/*
 * montauk_netlink.c - Genetlink interface for userspace communication
 *
 * Copyright (C) 2025
 */

#include <linux/module.h>
#include <net/genetlink.h>

#include "montauk.h"

/* Attribute policy for validation */
static const struct nla_policy montauk_policy[MONTAUK_ATTR_MAX + 1] = {
    [MONTAUK_ATTR_PID]          = { .type = NLA_U32 },
    [MONTAUK_ATTR_PPID]         = { .type = NLA_U32 },
    [MONTAUK_ATTR_COMM]         = { .type = NLA_NUL_STRING,
                                    .len = MONTAUK_COMM_LEN },
    [MONTAUK_ATTR_STATE]        = { .type = NLA_U8 },
    [MONTAUK_ATTR_UTIME]        = { .type = NLA_U64 },
    [MONTAUK_ATTR_STIME]        = { .type = NLA_U64 },
    [MONTAUK_ATTR_RSS_PAGES]    = { .type = NLA_U64 },
    [MONTAUK_ATTR_UID]          = { .type = NLA_U32 },
    [MONTAUK_ATTR_THREADS]      = { .type = NLA_U32 },
    [MONTAUK_ATTR_EXE_PATH]     = { .type = NLA_NUL_STRING,
                                    .len = MONTAUK_EXE_PATH_LEN },
    [MONTAUK_ATTR_START_TIME]   = { .type = NLA_U64 },
    [MONTAUK_ATTR_CMDLINE]      = { .type = NLA_NUL_STRING,
                                    .len = MONTAUK_CMDLINE_LEN },
    [MONTAUK_ATTR_PROC_ENTRY]   = { .type = NLA_NESTED },
    [MONTAUK_ATTR_PROC_COUNT]   = { .type = NLA_U32 },
};

/* Forward declarations */
static int montauk_cmd_get_snapshot(struct sk_buff *skb,
                                    struct genl_info *info);
static int montauk_cmd_get_stats(struct sk_buff *skb,
                                 struct genl_info *info);

/* Command operations */
static const struct genl_small_ops montauk_ops[] = {
    {
        .cmd    = MONTAUK_CMD_GET_SNAPSHOT,
        .doit   = montauk_cmd_get_snapshot,
    },
    {
        .cmd    = MONTAUK_CMD_GET_STATS,
        .doit   = montauk_cmd_get_stats,
    },
};

/* Genetlink family definition */
static struct genl_family montauk_genl_family = {
    .name       = MONTAUK_GENL_NAME,
    .version    = MONTAUK_GENL_VERSION,
    .maxattr    = MONTAUK_ATTR_MAX,
    .policy     = montauk_policy,
    .module     = THIS_MODULE,
    .small_ops  = montauk_ops,
    .n_small_ops = ARRAY_SIZE(montauk_ops),
};

/*
 * Add a single process entry to a netlink message
 */
static int montauk_add_proc_entry(struct sk_buff *msg,
                                  struct montauk_proc *proc)
{
    struct nlattr *nest;

    nest = nla_nest_start(msg, MONTAUK_ATTR_PROC_ENTRY);
    if (!nest)
        return -EMSGSIZE;

    if (nla_put_u32(msg, MONTAUK_ATTR_PID, proc->pid) ||
        nla_put_u32(msg, MONTAUK_ATTR_PPID, proc->ppid) ||
        nla_put_string(msg, MONTAUK_ATTR_COMM, proc->comm) ||
        nla_put_u8(msg, MONTAUK_ATTR_STATE, proc->state) ||
        nla_put_u64_64bit(msg, MONTAUK_ATTR_UTIME, proc->utime, 0) ||
        nla_put_u64_64bit(msg, MONTAUK_ATTR_STIME, proc->stime, 0) ||
        nla_put_u64_64bit(msg, MONTAUK_ATTR_RSS_PAGES, proc->rss_pages, 0) ||
        nla_put_u32(msg, MONTAUK_ATTR_UID, proc->uid) ||
        nla_put_u32(msg, MONTAUK_ATTR_THREADS, proc->nr_threads) ||
        nla_put_u64_64bit(msg, MONTAUK_ATTR_START_TIME, proc->start_time, 0)) {
        nla_nest_cancel(msg, nest);
        return -EMSGSIZE;
    }

    /* exe_path is optional (may be empty) */
    if (proc->exe_path[0] != '\0') {
        if (nla_put_string(msg, MONTAUK_ATTR_EXE_PATH, proc->exe_path)) {
            nla_nest_cancel(msg, nest);
            return -EMSGSIZE;
        }
    }

    nla_nest_end(msg, nest);
    return 0;
}

/*
 * Handler: MONTAUK_CMD_GET_SNAPSHOT
 * Dump all tracked processes
 */
static int montauk_cmd_get_snapshot(struct sk_buff *skb,
                                    struct genl_info *info)
{
    struct sk_buff *msg;
    struct rhashtable_iter iter;
    struct montauk_proc *proc;
    void *hdr;
    u32 count = 0;
    int ret;

    /* Allocate response message - large enough for many processes
     * Each process entry is ~120 bytes, so 256KB handles ~2000 processes
     */
    msg = nlmsg_new(256 * 1024, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

    hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
                      &montauk_genl_family, 0, MONTAUK_CMD_GET_SNAPSHOT);
    if (!hdr) {
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    /* Walk the process table */
    rhashtable_walk_enter(&montauk_proc_table, &iter);
    rhashtable_walk_start(&iter);

    while ((proc = rhashtable_walk_next(&iter)) != NULL) {
        if (IS_ERR(proc))
            continue;

        /* Just dump cached data - workqueue refreshes periodically */
        ret = montauk_add_proc_entry(msg, proc);
        if (ret == -EMSGSIZE) {
            /* Message full - this is a limitation for now
             * TODO: implement multi-part messages for large process counts
             */
            montauk_dbg("snapshot message full at %u procs\n", count);
            break;
        }
        count++;
    }

    rhashtable_walk_stop(&iter);
    rhashtable_walk_exit(&iter);

    /* Add process count */
    if (nla_put_u32(msg, MONTAUK_ATTR_PROC_COUNT, count)) {
        genlmsg_cancel(msg, hdr);
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    genlmsg_end(msg, hdr);

    montauk_dbg("snapshot: sending %u processes\n", count);

    return genlmsg_reply(msg, info);
}

/*
 * Handler: MONTAUK_CMD_GET_STATS
 * Return module statistics
 */
static int montauk_cmd_get_stats(struct sk_buff *skb,
                                 struct genl_info *info)
{
    struct sk_buff *msg;
    void *hdr;
    u64 uptime_sec;

    msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

    hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
                      &montauk_genl_family, 0, MONTAUK_CMD_GET_STATS);
    if (!hdr) {
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    uptime_sec = ktime_divns(ktime_sub(ktime_get_boottime(),
                                       montauk_stats.load_time),
                             NSEC_PER_SEC);

    if (nla_put_u32(msg, MONTAUK_ATTR_STAT_TRACKED,
                    atomic_read(&montauk_stats.tracked)) ||
        nla_put_u64_64bit(msg, MONTAUK_ATTR_STAT_FORKS,
                          atomic64_read(&montauk_stats.forks), 0) ||
        nla_put_u64_64bit(msg, MONTAUK_ATTR_STAT_EXECS,
                          atomic64_read(&montauk_stats.execs), 0) ||
        nla_put_u64_64bit(msg, MONTAUK_ATTR_STAT_EXITS,
                          atomic64_read(&montauk_stats.exits), 0) ||
        nla_put_u64_64bit(msg, MONTAUK_ATTR_STAT_OVERFLOWS,
                          atomic64_read(&montauk_stats.overflows), 0) ||
        nla_put_u64_64bit(msg, MONTAUK_ATTR_STAT_UPTIME_SEC, uptime_sec, 0)) {
        genlmsg_cancel(msg, hdr);
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    genlmsg_end(msg, hdr);

    return genlmsg_reply(msg, info);
}

/*
 * Register the genetlink family
 */
int montauk_netlink_init(void)
{
    int ret;

    ret = genl_register_family(&montauk_genl_family);
    if (ret) {
        montauk_err("failed to register genetlink family: %d\n", ret);
        return ret;
    }

    montauk_info("genetlink family '%s' registered\n", MONTAUK_GENL_NAME);
    return 0;
}

/*
 * Unregister the genetlink family
 */
void montauk_netlink_exit(void)
{
    genl_unregister_family(&montauk_genl_family);
    montauk_info("genetlink family unregistered\n");
}
