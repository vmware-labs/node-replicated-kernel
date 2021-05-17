# KPI: Kernel Public Interface

The Kernel Public Interface (KPI) is the lowest level user-space library that an
application links with. As the name suggests it is the common interface
definition between the kernel and user-space programs. It is special because it
is the only library that is shared between user and kernel code.

The KPI contains the syscall interface and various struct definitions that are
exchanged between the kernel and user-space. If in the future, we care about ABI
compatibility, we would not try to keep the syscall ABI compatible but would
rather enforce compatibility at the KPI boundary.

Typically, the KPI functionality will rarely be accessed directly by an
application. Instead, many parts of it are re-exported or wrapped by the
[vibrio](./Vibrio.html) library OS. The `kpi` code is found in `lib/kpi`.
