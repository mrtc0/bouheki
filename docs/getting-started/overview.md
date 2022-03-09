# Overview

bouheki detects (and prevents) two type of security events:

- [Network Access](../configuration/network-restriction/configuration.md)
- [File Access](../configuration/file-access-restriction/configuration.md)

bouheki can choose between the following two restriction target:

- Host-wide
- Container Only

bouheki can be run in two modes:

- Monitor Mode
- Block Mode

# Features

- Restriction rules can be created based on various process contexts
    - Process (Command) name
    - Parent Process (Command) name
    - UID / GID
- Monitoring and Blocking modes
    - Two modes are available: monitoring mode, which monitors and logs events, and blocking mode, which blocks events
- For Containers
    - Restrictions can be applied to containers only

# DEMO

[![asciicast](https://asciinema.org/a/475371.svg)](https://asciinema.org/a/475371)