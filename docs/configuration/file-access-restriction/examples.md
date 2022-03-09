# Examples

#### Allow access to all files

```yaml
file:
  mode: monitor
  target: host
  allow:
    - /
```

#### Block access to `/etc/passwd`

```yaml
file:
  mode: block
  target: host
  allow:
    - /
  deny:
    - /etc/passwd
```

#### Block all access to the `/root/.ssh` directory

```yaml
file:
  mode: block
  target: host
  allow:
    - /
  deny:
    - /root/.ssh
```

#### Block access to the `/proc/sys` directory in the container

```yaml
file:
  mode: block
  target: container
  allow:
    - /
  deny:
    - /proc/sys
```

!!! example

    ```shell
    root@ubuntu-impish:/# ls /proc/sys
    abi  debug  dev  fs  kernel  net  user  vm

    root@ubuntu-impish:/# docker run --privileged --rm -it ubuntu:latest bash
    root@9cf961922b00:/# ls /proc/sys
    ls: cannot open directory '/proc/sys': Operation not permitted
    ```

#### Block escapes from Privileged Container

```yaml
file:
  mode: block
  target: container
  allow:
    - /
  deny:
    - /proc/sysrq-trigger
    - /sys/kernel
    - /proc/sys/kernel
```

!!! example

  ```shell
  root@ubuntu-impish:/# docker run --privileged --rm -it ubuntu:latest bash
  root@e3b2ffe5b284:/# echo c > /proc/sysrq-trigger
  bash: /proc/sysrq-trigger: Operation not permitted

  root@e3b2ffe5b284:/# echo '/path/to/evil' > /sys/kernel/uevent_helper
  bash: /sys/kernel/uevent_helper: Operation not permitted

  root@e3b2ffe5b284:/# echo '|/path/to/evil' > /proc/sys/kernel/core_pattern
  bash: /proc/sys/kernel/core_pattern: Operation not permitted
  ```