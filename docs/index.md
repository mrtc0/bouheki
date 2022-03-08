# bouheki: Mandatory Access Control type of security audit tool with KRSI(eBPF+KRSI)

bouheki is a MAC(Mandatory Access Control) type of security audit tool.
KRSI (eBPF+LSM) can be used to control access based on context such as process name.

# Features

* Restriction rules based on process context, such as command name or UID and more
* Restrictions limited to containers (hosts are not restricted)
* Network Access Control
* File Access Control

# Demo

TBD

# LICENSE

bouheki's userspace program is licensed under MIT License.  
eBPF programs inside [pkg/bpf directory](https://github.com/mrtc0/bouheki/tree/master/pkg/bpf) are licensed under [GNU General Public License version 2](https://github.com/mrtc0/tree/master/pkg/bpf/LICENSE.md).  
