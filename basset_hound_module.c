/*
Project: BassetHound
Author: Rayne Cafaro and Jonathan Jang
Description: Kernel module to export the kernel task list.
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int __init basset_hound_init(void) {
	printk(KERN_INFO “Hello, World!\n”);
	return 0;
}

static void __exit basset_hound_exit(void) {
	printk(KERN_INFO “Goodbye, World!\n”);
}


module_init(basset_hound_init);
module_exit(basset_hound_exit);

MODULE_LICENSE(“GPL”);
MODULE_AUTHOR(“Rayne Cafaro & Jonathan Jang”);
MODULE_DESCRIPTION(“A Linux kernel module to export the kernel task list.”);


