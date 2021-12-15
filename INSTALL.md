# Installing bouheki

## Kernel Configuration

The kernel must have been compiled with the following flags set:

```shell
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_LSM=y
CONFIF_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INTO_BTF=y
```

Kernel compile flags can usually be checked by looking at /proc/config.gz or /boot/config-<kernel-version>.

Also, the `CONFIG_LSM` flag must contain `bpf`. This can also be controlled by boot parameters as following:

```shell
$ cat /etc/default/grub
...
GRUB_CMDLINE_LINUX="... lsm=landlock,lockdown,yama,apparmor,bpf"
...
```

## Download Binary

Download latest released binary from https://github.com/mrtc0/bouheki/releases .
