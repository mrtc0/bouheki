# Current configuration options


| Config | Type | Description |
|:------:|:----|:-----------:|
| `mode` | Enum with the following possible values: `monitor`, `block` | |
| `target` | Enum with the following possible values: `host`, `container` | |
| `cidr` | List containing the following sub-keys:<br><li>`allow: [cidr list]`</li><li>`deny: [cidr list]`</li>| |