/*
Project: BassetHound
File: basset_hound_module.c
Author: Rayne Cafaro and Jonathan Jang
Description: Kernel module to export the kernel task list and count of number of processes.
*/

#include <linux/init.h>                         // Needed for Linux Kernel Dev
#include <linux/module.h>                       // Needed for Linux Kernel Dev
#include <linux/kernel.h>	                // KERN_INFO
#include <linux/sched.h>	                // for_each_process, pr_info

/* @brief Output the tasklist. The fuction export_task_list gets the count of
 *        processes and lists each process to the kernel ring buffer.
 *
 */
static void export_task_list(void) {
	struct task_struct* task_list;                                          // Data struct describes processes in a system

	size_t count = 0;                                                       // Count of processes

	for_each_process(task_list) {
		pr_info("== %s [%d]\n", task_list->comm, task_list->pid);       // Output list of current process and its PID
		++count;                                                        // Incremment count
	}

	printk(KERN_INFO "== Basset_Count %zu\n", count);                       // Output count of processes to kernel

}

/* @brief Initializes the BassetHound module into the Linux Kernel.
 *
 */
static int __init basset_hound_init(void) {
	printk(KERN_INFO "insmod basset_hound_init.ko\n");                      // Output to kernel initialize message

	export_task_list();                                                     // Call to output processes in Kernel
                                                                                // Ring Buffer.

	return 0;
}

/* @brief Removes the BassetHound module from the Linux Kernel.
 *
 */
static void __exit basset_hound_exit(void) {
	printk(KERN_INFO "rmmod basset_hound_init.ko\n");                       // Output to kernel removal message
}


module_init(basset_hound_init);                                                 // Initializes the BassetHound Module
module_exit(basset_hound_exit);                                                 // Removes the BassetHound Module

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Rayne Cafaro & Jonathan Jang");
MODULE_DESCRIPTION("A Linux kernel module to export the kernel task list.");
