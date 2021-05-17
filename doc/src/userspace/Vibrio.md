# Vibrio

Virbio is the user-space library that provides most of the functionality
necessary to run applications in user-space. It is found in `lib/vibrio`.

## Memory

The user-space memory manager provides a `malloc` and `free` like interface for
C code and a `GlobalAlloc` implementation for rust programs. We rely on the
[same allocator](../architecture/Memory.html#dynamic-memory) that the kernel
uses for small--medium sized blocks (between 0 and 2 MiB). Everything else is
mapped directly by allocating memory with the map syscall.

## RumpRT

A rumpkernels is a componentized NetBSD kernel that can run in many different
environments. It contains file systems, a POSIX system call interface, many PCI
device drivers, a SCSI protocol stack, virtio, a TCP/IP stack, libc and
libpthread and more.

Vibrio has a `rumprt` module which provides the necessary low-level interface to
run a rumpkernel inside a user-space process (e.g., the
[rumpuser](https://man.netbsd.org/rumpuser.3) API and some more). This has the
advantage that it's possible to run many POSIX compatible programs out of the
box without building a fully-fledged POSIX compatibility layer into NrOS.

- Bare-metal and Xen implementations for [rumprun](https://github.com/rumpkernel/rumprun)
- [Some supported applications](https://github.com/rumpkernel/rumprun-packages)
- [PhD thesis about rumpkernels](https://research.aalto.fi/en/publications/flexible-operating-system-internals-the-design-and-implementation)

## Vibrio dependency graph

Vibrio uses the following crates / dependencies:

```log
vibrio
├── arrayvec
├── bitflags
├── crossbeam-utils
├── cstr_core
├── hashbrown
├── kpi
├── lazy_static
├── lineup
├── log
├── rawtime
├── rumpkernel
├── serde_cbor
├── slabmalloc
├── spin
└── x86
```
