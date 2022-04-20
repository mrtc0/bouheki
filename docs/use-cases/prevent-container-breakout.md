# Prevent Breakout Container

#### Block mount `/var/run/docker.sock` to container

```yaml
mount:
  mode: block
  target: host
  deny:
    - /var/run/docker.sock
```

!!! example

    ```shell
    # docker run --rm -it -v /var/run/docker.sock:/var/run/docker.sock ubuntu:latest bash
    docker: Error response from daemon: OCI runtime create failed: container_linux.go:380: starting container process caused: process_linux.go:545: container init caused: rootfs_linux.go:76: mounting "/var/run/docker.sock" to rootfs at "/var/run/docker.sock" caused: mount through procfd: operation not permitted: unknown.
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