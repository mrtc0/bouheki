# Change Log

## [Unreleased][unreleased]

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
