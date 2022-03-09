# Current configuration options


| Config | Type | Description |
|:------:|:----|:-----------:|
| `mode` | Enum with the following possible values: `monitor`, `block` | |
| `target` | Enum with the following possible values: `host`, `container` | |
| `cidr` | List containing the following sub-keys:<br><li>`allow: [cidr list]`</li><li>`deny: [cidr list]`</li>| |

!!! warning

    Currently file access restrictions cannot be based on process context (command name, UID, etc).  
    This is because the eBPF Program size becomes too large, and it is failed pass by the eBPF Verifier's limitations.  
    If you can create a better eBPF program, please contribute!