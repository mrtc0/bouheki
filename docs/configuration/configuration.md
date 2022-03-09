# Configuration

bouheki's configuration file is a YAML file containing a collection of `key: value` or `key: [value list]` pairs.

## Current configuration options

| Config | Type | Description |
|:------:|:----|:-----------:|
| `network` | List (see [Network Restiction](./network-restriction/configuration.md)) | Rule for network restrictions. |
| `files` | List (see [File Access Restiction](./file-access-restriction/configuration.md)) | Rule for file access restrictions. |
| `log` | List containing the following sub-keys: <br><li>`format: [json|text]`</li><li>`output: <path>`</li><li>`max_size:`: Maximum size to rotate (MB). Default: 100MB</li><li>`max_age`: Period for which logs are kept. Default: 365</li>| Log configuration. |