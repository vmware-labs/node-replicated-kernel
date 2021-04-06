# Init

The simplest user-space test program.

## Manual build

Invoke:

```
cargo rustc -- -C link-arg=-nostartfiles -Clink-arg=-static -Clink-arg=-zmax-page-size=0x200000
```