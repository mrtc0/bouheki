# bouheki ToDos

This documentation is a todo list of things bouheki is planning to add or modify in the future.

# Support some LSM hook points

Currently, bouheki can only restrict network communication, but we are thinking of supporting other [LSM hook points](https://www.kernel.org/doc/html/v5.2/security/LSM.html).  

## File access

It should be possible to restrict access to the file by attaching it to `LSM/file_open`.  

# Change config format

The more LSM hook points support, the more complicated the configuration becomes.  
Therefore, we will prepare a separate configuration file for each hook point.

```yaml
version: v1
kind: RestrictNetwork
config:
  - cidr:
      allow: []
      deny: []
  ...
```

We would like to be able to use multiple restriction settings (for example, we can have a restriction rule for each application), but it is difficult because we use eBPF Map.  

