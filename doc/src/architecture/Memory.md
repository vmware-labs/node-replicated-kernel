# Memory

## Kernel address space

The kernel address space layout follows a simple scheme: All physical memory is
identity mapped with a constant offset `KERNEL_BASE` in the kernel address
space. Therefore, any physical address can be accessed in the kernel by adding
`KERNEL_BASE` to it.

All physical memory is always accessible in the kernel and does not need to
mapped/unmapped at runtime. The kernel binary is linked as position independent
code, it is loaded into physical memory and then relocated to run at the kernel
virtual address (`KERNEL_BASE` + physical address).

<figure>
  <img src="../diagrams/AddressSpaceLayout.png" alt="Overview of address space layout in the OS"/>
  <figcaption>
    A view of different address spaces in bespin (physical, kernel, user).
  </figcaption>
</figure>

## Physical memory

Physical memory allocation and dynamic memory allocation for kernel data
structures are two basic subsystems that do not rely on NR. Replicated
subsystems often require physical frames, but that allocation operation itself
should not be replicated. For example, when installing a mapping in a page
table, each page table entry should refer to the same physical page frame on all
replicas (though, each replica should have its own page tables). If allocator
state were replicated, each allocation operation would be repeated on each
replica, breaking this.

At boot time, the affinity for memory regions is  identified, and memory is
divided into per-NUMA node caches (NCache). The NCache statically partitions
memory further into two classes of 4 KiB and 2 MiB frames. Every core has a
local TCache of 4 KiB and 2 MiB frames for fast, no-contention allocation when
it contains the requested frame size. If it is empty, it refills from its local
NCache. Similar to slab allocators, Bespin' TCache and NCache implement a cache
frontend and backend that controls the flow between TCaches and NCaches.

<figure>
  <img src="../diagrams/NCache-TCache.png" alt="NCache and TCache physical frame allocators"/>
  <figcaption>
    Shows a global per-NUMA NCache and a per-core TCache. Cores allocate 4K or 2M
    pages directly from the TCache which may refill from the NCache when empty (grow).
    TCaches and NCaches both hold frames in stacks to allows for quick allocation
    and deallocation of frames.
  </figcaption>
</figure>

## Dynamic memory

Since Bespin is implemented in Rust, memory management is greatly simplified by
relying on the compiler to track the lifetime of allocated objects. This
eliminates a large class of bugs (use-after-free, uninitialized memory *etc.*),
but the kernel still has to explicitly deal with running out of memory. Bespin
uses fallible allocations and intrusive data structures to handle out-of-memory
errors gracefully.

The dynamic memory allocator in bespin provides an implementation for the [Rust
global allocator
interface](https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html). It uses
size classes and different allocators per class (*e.g.,* it's a
segregated-storage allocator), while incorporating some of the simple and
effective ideas from slab allocation: For each size class, 2MiB or 4 KiB frames
are used which are sliced into equal sized objects of a given class. A bitfield
at the end of every frame tracks the meta-data for objects within the frame
(*e.g.,* to determine if its allocated or not).

<figure>
  <img src="../diagrams/Slabmalloc.png" alt="Schematic overview of the dynamic memory allocator"/>
  <figcaption>
    The dynamic memory allocator for kernel objects in bespin. It shows an allocator
    containing two frames for less than 16 byte objects. Each frame contains
    a few allocated slots along with per-frame meta-data (prev, next pointer) and
    metadata to indicate allocated blocks. Typically, one dynamic memory allocator
    per core is instantiated.
  </figcaption>
</figure>