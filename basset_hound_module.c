/*
Project: BassetHound
Author: Rayne Cafaro and Jonathan Jang
Description: Kernel module to export the kernel task list.
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>

static void export_task_list(void) {
	struct task_struct* task_list;
	
	for_each_process(task_list) {
		pr_info("== %s [%d]\n", task_list->comm, task_list->pid);
	}

}

static int __init basset_hound_init(void) {
	printk(KERN_INFO "insmod basset_hound_init.ko\n");

	export_task_list();

	return 0;
}

static void __exit basset_hound_exit(void) {
	printk(KERN_INFO "rmmod basset_hound_init.ko\n");
}


module_init(basset_hound_init);
module_exit(basset_hound_exit);

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Rayne Cafaro & Jonathan Jang");
MODULE_DESCRIPTION("A Linux kernel module to export the kernel task list.");


