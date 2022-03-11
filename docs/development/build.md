# Build

```shell
$ vagrant ssh

$ cd /opt/go/src/github.com/mrtc0/bouheki/
$ make libbpf-static
$ make build
```

# Test

```shell
$ make test
# Runs tests that require loading the eBPF program.
# This is used in integration testing, where events are actually generated and tested
$ make test/integration
```
