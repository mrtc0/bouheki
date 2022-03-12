# Installation

## Requirements

* Linux Kernel >= 5.8.0
  * BTF(`CONFIG_DEBUG_INFO_BTF`) must be enabled.
  * BPF LSM(`CONFIG_LSM` with `bpf`) must be enabled. This parameter can also be changed in the boot parameter.

### Kernel Configuration

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

Kernel compile flags can usually be checked by looking at `/proc/config.gz` or `/boot/config-<kernel-version>`.

Also, the `CONFIG_LSM` flag must contain `bpf`. This can also be controlled by boot parameters as following:

```shell
$ cat /etc/default/grub
...
GRUB_CMDLINE_LINUX="... lsm=lockdown,yama,apparmor,bpf"
...
```

Finary, run `update-grub2`.

```shell
sudo update-grub2
```

### Linux distributions and supported kernels

| Distro Name | Distro Version | Kernel Version |
|:-----------:|:--------------:|:--------------:|
| Ubuntu | >= 20.10 | 5.8+ |
| Fedora | >= 33 | 5.8+ |

## Install

Download latest released binary from https://github.com/mrtc0/bouheki/releases

```shell
$ wget https://github.com/mrtc0/bouheki/releases/download/v0.0.3/bouheki_0.0.3_Linux_x86_64.tar.gz
$ tar xzf bouhki_0.0.3_Linux_x86_64.tar.gz
$ sudo install bouheki /usr/local/bin/bouheki
```