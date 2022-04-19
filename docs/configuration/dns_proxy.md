# DNS Proxy

If you want to control access by [specifying domain names](./network-restriction/configuration.md), you need to select "Periodic Name Resolution" or "Change DNS Server".  
Default is "Periodic Name Resolution", but recommended is "Change DNS Server".

## Periodic Name Resolution (Default)

Periodically resolves domain names and updates IP addresses in the Allow / Deny list.  

!!! warning

    It is designed to perform name resolution when the TTL value reaches 0. This means that depending on the timing, there may be rare cases where communication to an restricted address is possible, or where communication to an restricted address is not possible. This often occurs in domains with short TTL, such as AWS S3.

## Change DNS Server (Recommend)

If `dns_proxy` is enabled, bouheki will start DNS Proxy. Specify `127.0.0.1` and `172.17.0.1` (default bridge for docker) for `nameserver` in `/etc/resolv.conf`.
If the domain to be name resolved is restricted, update the IP address in the Allow / Deny list.


!!! warning

    If you are using systemd-resolved, change `/etc/systemd/resolved.conf` instead of `/etc/resolv.conf`.  
    For example:

    ```
    DNS=127.0.0.1 172.17.0.1
    ```

## Current configuration options

| Config | Type | Description |
|:------:|:----|:-----------:|
| `enable` | Enum with the following possible values: `true`, `false` | Whether to enable DNS Proxy or not. Default is `false`. |
| `upstreams` | List | Lisf of DNS Servers. |