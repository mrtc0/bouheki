# Prevent SSRF Attacks

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