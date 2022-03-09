# bouheki: KRSI(eBPF+LSM) based Linux security auditing tool

bouheki is KRSI(eBPF+LSM) based Linux security auditing tool.  
Security events can be audited and blocked based on the container of the process, and restrictions can be applied to container environments.

# Features

* Restriction rules based on process context, such as command name or UID and more
* Restrictions limited to containers (hosts are not restricted)
* Network Access Control
* File Access Control

# Demo

[![asciicast](https://asciinema.org/a/475371.svg)](https://asciinema.org/a/475371)

# LICENSE

bouheki's userspace program is licensed under MIT License.  
eBPF programs inside [pkg/bpf directory](https://github.com/mrtc0/bouheki/tree/master/pkg/bpf) are licensed under [GNU General Public License version 2](https://github.com/mrtc0/tree/master/pkg/bpf/LICENSE.md).  
