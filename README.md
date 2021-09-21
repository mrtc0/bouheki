# bouheki: Tool for Preventing Data Exfiltration with eBPF

**bouheki** is a KSRI implementation using LSM Hook by eBPF. 
Flexibility to apply restricted network policies to specific resources such as processes and containers.

# Network Restriction

* While firewalls such as iptables apply to the entire machine, bouheki can be restricted on a per-container or per-process basis.
* bouheki does not restrict ingress, only egress.

# Roadmap

- [x] Restriction on containers only
- [ ] Restriction on specified commands
- [ ] Restriction on specified UID / GID
- [ ] Policy Propagation with gRPC API

# Getting Started

## 0. Requirements

* Linux Kernel >= 5.8.0
  * BTF(`CONFIG_DEBUG_INFO_BTF`) must be enabled.
  * BPF LSM(`CONFIG_LSM` with `bpf`) must be enabled. This parameter can also be changed in the boot parameter.

### Linux distributions and supported kernels

| Distro Name | Distro Version | Kernel Version |
|:-----------:|:--------------:|:--------------:|
| Ubuntu "Groovy Gorilla"	| 20.10 | 5.8+ |
| Fedora | 33 | 5.8+ |

## 1. Install

Download latest released binary from https://github.com/mrtc0/bouheki/releases

## 2. Configuration

Write the network restriction policy in YAML.  
This policy allows access to 10.0.1.1/24 only, but does not allow access to 10.0.1.10/32.

```yaml
# block.yaml
network:
  # monitor or block
  mode: block
  # host or container
  target: host
  allow:
    - 10.0.1.1/24
    - 127.0.0.1/24
  # Override "allow" list with exceptions
  deny: # []
    - 10.0.1.10/32
```

Run with the policy.

```shell
$ sudo bouheki --config block.yaml
```

## 3. Test

```shell
$ curl -k -I https://10.0.1.1
HTTP/1.1 200 OK

$ curl -k -I https://10.0.1.10
curl: (7) Couldn't connect to server

$ curl -k -I https://example.com
curl: (7) Couldn't connect to server
```

## 4. Inspect Logs

The log will record the blocked events.

```shell
$ sudo ./bouheki --config config/sample.yaml
INFO[0003] Traffic is trapped in the filter.             Action=block Addr=10.0.1.10 Comm=curl Hostname=sandbox PID=294293 Port=443
INFO[0026] Traffic is trapped in the filter.             Action=block Addr=93.184.216.34 Comm=curl Hostname=sandbox PID=294356 Port=443
INFO[0026] Traffic is trapped in the filter.             Action=block Addr=93.184.216.34 Comm=curl Hostname=sandbox PID=294356 Port=443
```

# Development

TBD

# Test

```shell
$ make test
```
