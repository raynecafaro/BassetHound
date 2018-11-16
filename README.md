# BassetHound
A Linux kernel module and userland utility pair to detect hidden processes.

## Loading the Kernel Module Separately
The kernel module exports the kernel task list from kernel space to user space via dmesg. The task list is a linked list of task_structs are the linux kernel representation of processes.

```
insmod basset_hound_module.ko
lsmod | grep basset 
rmmod basset_hound_module.ko
```

## Requirements

### Kernel Module Compilation Requirements
The included kernel header files:

```
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>	                // KERN_INFO
#include <linux/sched.h>	                // for_each_process, pr_info
```

The following commands will install the kernel headers that are necessary for compiliation.
Ubuntu/Debian:
```
apt-get install build-essential linux-headers-`uname -r`
```
Centos/RHEL:
```
yum install kernel-devel linux-headers-`uname -r`
```

### Run Requirements for basset_hound.py
- Python3
- Compiled basset_hound_module.ko

By default, basset_hound.py looks for the basset_hound_module.ko in the current working directory.  The flag "-lkm" can be passed to insert the kernel module if it resides in a different directory.

```
Python3 basset_hound.py -lkm /Path/To/basset_hound_module.ko
```

- basset_hound.py must be run with UID 0 (sudo or root). 

## Authors

[Rayne Cafaro](https://github.com/raynecafaro)
[Jonathan Jang](https://github.com/jwj3767)

## License

This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/raynecafaro/BassetHound/blob/master/LICENSE) file for details
