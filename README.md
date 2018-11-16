# BassetHound
A Linux kernel module and userland utility pair to detect Linux kernel module (LKM) rootkits.

## Running the Kernel Module

```
insmod basset_hound_module.ko
lsmod | grep basset
rmmod basset_hound_module.ko
```

### Prerequisites

```
apt-get install build-essential linux-headers-`uname -r`
```

## Authors

[Rayne Cafaro](https://github.com/raynecafaro)
[Jonathan Jang](https://github.com/jwj3767)

## License

This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/raynecafaro/BassetHound/blob/master/LICENSE) file for details
