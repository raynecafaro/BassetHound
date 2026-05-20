/*
Project: BassetHound
File: basset_hound_module.c
Author: Rayne Cafaro and Jonathan Jang (Modernized by Antigravity)
Description: Kernel module to export the kernel task list using Netlink sockets.
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/netlink.h>

#define NETLINK_BASSET 31

static struct sock *nl_sock = NULL;

static void send_chunk(int pid, const char *data, size_t len, bool done) {
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    int res;

    if (len == 0 && !done) return;

    skb_out = nlmsg_new(len, GFP_KERNEL);
    if (!skb_out) {
        pr_err("basset_hound: failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, done ? NLMSG_DONE : 0, len, 0);
    if (!nlh) {
        pr_err("basset_hound: nlmsg_put failed\n");
        nlmsg_free(skb_out);
        return;
    }

    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    if (len > 0) {
        memcpy(nlmsg_data(nlh), data, len);
    }

    res = nlmsg_unicast(nl_sock, skb_out, pid);
    if (res < 0) {
        pr_debug("basset_hound: error sending message to user: %d\n", res);
    }
}

static void basset_hound_nl_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    int pid;
    struct task_struct *task;
    char *buf;
    size_t buf_len = 0;
    size_t max_buf = 16384; // 16KB buffer to pack processes

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid; // PID of user space process

    buf = kmalloc(max_buf, GFP_KERNEL);
    if (!buf) {
        pr_err("basset_hound: failed to allocate memory\n");
        return;
    }

    rcu_read_lock();
    for_each_process(task) {
        char line[256];
        int len = snprintf(line, sizeof(line), "%d\t%s\n", task->pid, task->comm);
        if (len > 0) {
            if (buf_len + len < max_buf - 1) {
                memcpy(buf + buf_len, line, len);
                buf_len += len;
            } else {
                rcu_read_unlock();
                send_chunk(pid, buf, buf_len, false);
                buf_len = 0;
                rcu_read_lock();
                memcpy(buf + buf_len, line, len);
                buf_len += len;
            }
        }
    }
    rcu_read_unlock();

    send_chunk(pid, buf, buf_len, true);
    kfree(buf);
}

static int __init basset_hound_init(void) {
    struct netlink_kernel_cfg cfg = {
        .input = basset_hound_nl_recv_msg,
    };

    pr_info("basset_hound: initializing module via netlink\n");

    nl_sock = netlink_kernel_create(&init_net, NETLINK_BASSET, &cfg);
    if (!nl_sock) {
        pr_err("basset_hound: error creating netlink socket\n");
        return -ENOMEM;
    }

    return 0;
}

static void __exit basset_hound_exit(void) {
    pr_info("basset_hound: removing module\n");
    if (nl_sock) {
        netlink_kernel_release(nl_sock);
    }
}

module_init(basset_hound_init);
module_exit(basset_hound_exit);

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Rayne Cafaro & Jonathan Jang");
MODULE_DESCRIPTION("A Linux kernel module to export the kernel task list via Netlink.");
