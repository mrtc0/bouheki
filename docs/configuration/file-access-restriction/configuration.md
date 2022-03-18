# Current configuration options


| Config | Type | Description |
|:------:|:----|:-----------:|
| `enable` | Enum with the following possible values: `true`, `false` | Whether to enable restrictions or not. Default is `true`. |
| `mode` | Enum with the following possible values: `monitor`, `block` | If `monitor` is specified, events are only logged. If `block` is specified, network access is blocked. |
| `target` | Enum with the following possible values: `host`, `container` | Selecting `host` applies the restriction to the host-wide. Selecting `container` will apply the restriction only to containers. |
| `allow` | A list of allow file paths | |
| `deny` | A list of allow file paths | |

!!! warning

    Currently file access restrictions cannot be based on process context (command name, UID, etc).  
    This is because the eBPF Program size becomes too large, and it is failed pass by the eBPF Verifier's limitations.  
    If you can create a better eBPF program, please contribute!