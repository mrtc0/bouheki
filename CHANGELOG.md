# Change Log

## [Unreleased][unreleased]

## [0.0.8] 2022-04-20

### Fix

bouheki no longer modifies `/etc/resolv.conf`. If you use bouheki's DNS proxy server, you must manually modify `/etc/resolv.conf`.

### Added

#### DNS Proxy [#24](https://github.com/mrtc0/bouheki/pull/24)

Listen to DNS Proxy servers to address a bug ([#17](https://github.com/mrtc0/bouheki/issues/17)) that allows bypassing the limit when the TTL reaches 0.  


## [0.0.8] 2022-03-29

### Fix

#### Fix TTL-based DNS Resolver [#19](https://github.com/mrtc0/bouheki/pull/19)


## [0.0.7] 2022-03-27

### Added

#### Support for labels in log

Logs can contain arbitrary labels in key/value format.  
For example:

```yaml
log:
  labels:
    environment: produdction
    role: app
```

```json
{
  "Action": "BLOCKED",
  "Addr": "52.219.1.53",
  "Comm": "curl",
  ...
  "environment": "production",
  "role": "app",
  "time": "2022-03-27T13:33:17Z"
}
```

### Fix

#### TTL-based name resolution instead of periodically [#18](https://github.com/mrtc0/bouheki/pull/18)

Workarounds for [#17](https://github.com/mrtc0/bouheki/issues/17).

#### Context logger

Log context was not set correctly.

## [0.0.6] 2022-03-23

### Fix

#### Static Link

bouheki's binary is now statically complaied.

## [0.0.5] 2022-03-18

### Added

#### Support for mount restrictions [#10](https://github.com/mrtc0/bouheki/pull/10)

Added new restriction for mount event. This prevents file mounts such as `/var/run/docker.sock`.

```yaml
mount:
  mode: block
  target: host
  deny:
    - /var/run/docker.sock
```

#### Added option to disable restrictions

```yaml
network:
  enable: true
  ...
files:
  enable: false # File access restrictions do not apply
```

## [0.0.4] 2022-03-12

### Added

#### Support for file access restrictions [#6](https://github.com/mrtc0/bouheki/pull/7)

File open can now be restricted by attaching lsm/open.  
For example, Access to `/etc/passwd` and `/etc/test` can be disabled with the following configuration:

```yaml
network:
  mode: block
  target: host
  cidr:
    allow:
      - 0.0.0.0/0
files:
  mode: block
  target: container
  allow:
    - '/'
  deny:
    - '/etc/passwd'
    - '/etc/test'
log:
  format: json
```

### Changed

#### update libbpfgo and static link [#9](https://github.com/mrtc0/bouheki/pull/9)

libbpfgo updated to `v0.2.4-libbpf-0.6.1`. With this change, libbpf is managed a a submodule.  
Also, libbpf is now statically linked.

```bash
$ ldd bouheki
        linux-vdso.so.1 (0x00007fff9a8ae000)
        libelf.so.1 => /lib/x86_64-linux-gnu/libelf.so.1 (0x00007fc5e2761000)
        libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007fc5e2745000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fc5e251d000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fc5e2788000)
```

#### Support for restrictions by domain name [#5](https://github.com/mrtc0/bouheki/pull/5)

Restrictions by domain name are now possible.  
Since it is difficult to hook domain name resolution in eBPF, we will resolve it in the userspace program.  
Periodically perform name resolution in the userspace programs to update the eBPF Map.  

This will support the following settings:

```yaml
network:
  mode: block
  target: host
  cidr:
    allow:
      - 0.0.0.0/0
    deny: []
  domain:
    deny:
      # Connection to example.com will be blocked
      - example.com
```

This is an initiative by GMO Pepabo, Inc. through its internship program for students.  
Thanks @n01e0

## [v0.0.3] 2022-02-21

### Added

#### Support for IPv6 communication. [#2](https://github.com/mrtc0/bouheki/pull/2)

It can monitor and block the communication of specified IPv6 address with the following settings:

```yaml
network:
  mode: block
  target: host
  cidr:
    allow:
      - 0.0.0.0/0
      - ::/0
    deny:
      - 2001:3984:3989::3/128
log:
  format: json
```

This is an initiative by GMO Pepabo, Inc. through its internship program for students.  
Thanks @n01e0

## [v0.0.2] 2021-11-10

### Added

#### Logging parent process command

Output the command name of the parent process to the log.

### Changed

#### Do not audited communications with destination port of `0`

If the destination port is `0`, it will not be audited.
In some cases, such as getaddrinfo(), sin_port is set to `0`. Not audited because no communication actually occurs.

## [v0.0.1] 2021-09-23

Initial Release :tada:
