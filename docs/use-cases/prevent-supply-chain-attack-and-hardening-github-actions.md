# Prevent Supply Chain Attacks and Hardening GitHub Actions Self-hosted Runner

In recent years, there have been many incidents of credentials being compromised from CI / CD environments due to supply chain attacks.  
Prevent against supply chain attacks signature and hash verification, and more, but restrict egress is another measure that should be taken.
bouheki can be installed in a CI/CD environment to restrict network communication by domain name or process name.

## Hardening GitHub Actions Self-hosted Runner

Hardening a Workflow running on GitHub Actions Self-hosted Runner is done in the following steps:

### 1. Install bouheki

Install bouheki with reference to [Installation](../getting-started/installation.md).

### 2. Create the bouheki configuration file

```yaml
network:
  mode: block
  target: host
  cidr:
    allow: ["8.8.8.8/32", "8.8.4.4/32", "127.0.0.1/32", "10.0.0.8", "172.16.0.0/12", "192.168.0.0/16"] # Add the DNS Server, etc. to be used.
  domain:
    allow:
      # https://docs.github.com/ja/actions/hosting-your-own-runners/about-self-hosted-runners#
      - "github.com",
      - "api.github.com",
      - "codeload.github.com",
      - "objects.github.com",
      - "objects.githubusercontent.com",
      - "objects-origin.githubusercontent.com",
      - "github-releases.githubusercontent.com",
      - "github-registry-files.githubusercontent.com",
dns_proxy:
  enable: true
  upstreams:
    - 8.8.8.8
    - 8.8.4.4
log:
  format: json
```

### 3. Change the DNS Server to be used

Change `/etc/resolv.conf` to use bouheki's DNS Proxy.  
bouheki DNS Proxy also listens on `172.17.0.1`, this default bridge for Docker; this IP address must also be specified in the `nameserver` so that the Docker container can resolve names.

```shell
$ cat /etc/resolv.conf
nameserver 127.0.0.1
nameserver 172.17.0.1
search .
```

If you are using systemd-resolved, do not modify `/etc/resolv.conf`. You must change `/etc/systemd/resolved.conf`.

```shell
# cat /etc/systemd/resolved.conf
[Resolve]
DNS=127.0.0.1 172.17.0.1

# systemctl restart systemd-resolved
```

### 4. Execute the Actions Workflow

!!! warning
    WIP

https://github.com/mrtc0/bouheki-runner allows you to restrict access to per Workflows.