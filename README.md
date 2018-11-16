# BassetHound
A Linux kernel module and userland utility pair to detect hidden processes.

## Running the Kernel Module Separately

```
insmod basset_hound_module.ko
lsmod | grep basset
rmmod basset_hound_module.ko
```

## Requirements

### Kernel Module Compile Requirements
The necessary kernel headers:

```
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>	                // KERN_INFO
#include <linux/sched.h>	                // for_each_process, pr_info
```

### To Run
- Python3
- Compiled KO : The command below will install the kernel headers needed

```
apt-get install build-essential linux-headers-`uname -r`
```

- Passing of Flags
By default, Python looks for the Linux Kernel Module in the current directory where BassetHound is being run. Therefore, in order to remedy this issue the flag "-lkm" must be passed.

```
Python3 basset_hound.py -lkm /Path/To/basset_hound_module.ko
```

- User must also have sudo privileges or root access with UID 0

## Authors

[Rayne Cafaro](https://github.com/raynecafaro)
[Jonathan Jang](https://github.com/jwj3767)

## License

This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/raynecafaro/BassetHound/blob/master/LICENSE) file for details
