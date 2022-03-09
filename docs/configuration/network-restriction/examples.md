# Examples

#### Allow all network connections

Allows all network communications and monitors their connections.

```yaml
network:
  mode: monitor
  target: host
  cidr:
    allow: ['0.0.0.0/0']
```

#### Block specify Private Networks

Block access to `192.168.1.1/24` and `10.0.1.1/24`.

```yaml
network:
  mode: block
  target: host
  cidr:
    allow: ['0.0.0.0/0']
    deny:
      - 192.168.1.1/24
      - 10.0.1.1/24
```

#### Block Metadata service API

Block access to the public cloud Metadata Service. This is a mitigation measure against SSRF, etc.

```yaml
network:
  mode: block
  target: host
  cidr:
    allow: ['0.0.0.0/0']
    deny:
      - 169.254.169.254/32
```

#### Block connections to the specified domain

Block connections to `example.com`. bouheki periodically looks up IP addresses, so it keeps up with IP address changes.

```yaml
network:
  mode: block
  target: host
  cidr:
    allow: ['0.0.0.0/0']
  domain:
    deny:
      - example.com
```

#### Block network connections of containers

Allow communication from the host, but block communication from the containers.

```yaml
network:
  mode: block
  target: container
  cidr:
    allow: ['0.0.0.0/0']
  domain:
    deny:
    - example.com
```

!!! example

    ```shell
    vagrant@ubuntu-impish:~$ curl -I https://example.com
    HTTP/2 200

    vagrant@ubuntu-impish:~$ sudo docker run --rm -it curlimages/curl https://example.com
    curl: (7) Couldn't connect to server
    ```

#### Block all connections from curl

```yaml
network:
  mode: monitor
  target: container
  cidr:
    allow: ['0.0.0.0/0']
  command:
    deny: ['curl']
```

!!! example

    ```shell
    vagrant@ubuntu-impish:~$ curl -I https://example.com
    curl: (6) Could not resolve host: example.com

    vagrant@ubuntu-impish:~$ wget https://example.com -O /dev/null
    --2022-03-09 14:45:11--  http://example.com/
    Resolving example.com (example.com)... 93.184.216.34
    Connecting to example.com (example.com)|93.184.216.34|:80... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 1256 (1.2K) [text/html]
    Saving to: ‘/dev/null’

    /dev/null               100%[============================>]   1.23K  --.-KB/s    in 0s

    2022-03-09 14:45:12 (70.1 MB/s) - ‘/dev/null’ saved [1256/1256]
    ```

#### Block all connections by users with UID 1000

Setting that blocks all network access for UID 1000 user, but does not apply restrictions to UID 0 (root).

```yaml
network:
  mode: monitor
  target: container
  cidr:
    allow: ['0.0.0.0/0']
  uid:
    allow: [0]
    deny: [1000]
```

!!! example

    ```shell
    vagrant@ubuntu-impish:~$ id
    uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)

    vagrant@ubuntu-impish:~$ curl -I https://example.com
    curl: (6) Could not resolve host: example.com

    vagrant@ubuntu-impish:~$ sudo curl -I https://example.com
    HTTP/2 200
    ```