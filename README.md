# bouheki: Tool for Preventing Data Exfiltration with eBPF

**bouheki** is a KSRI implementation using LSM Hook by eBPF. 
Flexibility to apply restricted network policies to specific resources such as processes and containers.

# Features and Network Restrictions

* While firewalls such as iptables apply to the entire machine, bouheki can be restricted on a per-container or per-process basis.
* bouheki does not restrict ingress, only egress.

# Getting Started

## 0. Requirements

* Linux Kernel >= 5.8.0
  * BTF(`CONFIG_DEBUG_INFO_BTF`) must be enabled.
  * BPF LSM(`CONFIG_LSM` with `bpf`) must be enabled. This parameter can also be changed in the boot parameter.

See [INSTALL.md](INSTALL.md) for details on installation.

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

See [config directory](./config) for more configuration examples.

```yaml
# block.yml
network:
  # Block or monitor the network.
  # If block is specified, communication that matches the policy will be blocked.
  mode: block # monitor or block. Default: monitor
  # Restriction to the whole host or to a container
  # If a container is specified, only the container's communication will be restricted. This is determined by the value of namespace
  target: host # host or container. Default: host
  cidr:
    allow:
      - 10.0.1.1/24
      # - 127.0.0.1/24
    # Override "allow" list with exceptions. Default: []
    deny: # []
      - 10.0.1.10/32
  # Restrictions by domain.
  domain:
    allow: []
    deny: # []
      - example.com
  # Restrictions by command name (optional).
  command:
    # Default: empty. All command will be allowed.
    allow: []
    # - curl
    # Default: empty. All command will be allowed.
    deny: []
    #  - wget
    #  - nc
  # Restrictions by UID (optional).
  uid:
    allow: []
    deny: []
  # Restrictions by GID (optional).
  gid:
    allow: []
      # - 0
    deny: []
      # 1000
log:
  # Log format(json or text). Default: json
  format: json
  # Specified log file location. Default: stdout
  # output: /var/log/bouheki.log.json
  # Maximum size to rotate (MB)
  # max_size: 100
  # Period for which logs are kept
  # max_age: 365
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
{
  "Action": "BLOCKED",
  "Addr": "10.0.1.71",
  "Comm": "curl",
  "Hostname": "sandbox",
  "PID": 790791,
  "ParentComm": "bash",
  "Port": 443,
  "Protocol": "TCP",
  "level": "info",
  "msg": "Traffic is trapped in the filter.",
  "time": "2021-09-23T12:47:55Z"
}
{
  "Action": "BLOCKED",
  "Addr": "93.184.216.34",
  "Comm": "curl",
  "Hostname": "sandbox",
  "PID": 790823,
  "ParentComm": "bash",
  "Port": 443,
  "Protocol": "TCP",
  "level": "info",
  "msg": "Traffic is trapped in the filter.",
  "time": "2021-09-23T12:49:29Z"
}
```

# Development

```shell
$ vagrant up && vagrant reload
$ vagrant ssh

$ cd /opt/go/src/github.com/mrtc0/bouheki/
$ make build
```

# Test

```shell
$ make test && make test/integration
```

# LICENSE

bouheki's userspace program is licensed under MIT License.  
eBPF programs inside [pkg/bpf directory](pkg/bpf) are licensed under [GNU General Public License version 2](./pkg/bpf/LICENSE.md).  
