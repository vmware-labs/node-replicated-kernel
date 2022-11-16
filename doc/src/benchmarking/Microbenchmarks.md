# Microbenchmarks

## File-system

The code contains an implementation of the
[fxmark](https://www.usenix.org/system/files/conference/atc16/atc16_paper-min.pdf)
benchmark suite. The benchmark code is located at `usr/init/src/fxmark`.

To run the fxmark benchmarks invoke the following command:

```bash
RUST_TEST_THREADS=1 cargo test --test s10* -- s10_fxmark_bench --nocapture
```

fxmark supports several different file benchmarks:

* *drbh*: Read a shared block in a shared file
* *drbl*: Read a block in a private file.
* *dwol*: Overwrite a block in a private file.
* *dwom*: Overwrite a private block in a shared file.
* *mwrl*: Rename a private file in a private directory.
* *mwrm*: Move a private file to a shared directory.
* *mix*: Access/overwrite a random block (with fixed percentages) in a shared
  file.

> By default the integration test might not run all benchmarks, you can modify
> the CI code to change what benchmarks are run or study it to determine how to
> supply the correct arguments to `run.py`.

## Address-space

The following integration tests benchmark the address-space in nrk:

* `s10_vmops_benchmark`: This benchmark repeatedly inserts the same frame over
  and over in the process' address space, while varying the number of cores that
  do insertions. Every core works in its own partition of the address space. The
  system measures the throughput (operations per second).

* `s10_vmops_latency_benchmark`: Same as `s10_vmops_benchmark`, but measure
  latency instead of throughput.

* `s10_vmops_unmaplat_latency_benchmark`: The benchmark maps a frame in the
  address space, then spawns a series of threads on other cores that access the
  frame, afterwards it unmaps the frame and measures the latency of the unmap
  operation (the latency is dominated by completing the TLB shootdown protocol
  on all cores).

* `s10_shootdown_simple`: The benchmark measures the overhead in the kernel for
  programming the APIC and sending IPIs to initiate and complete the shootdown
  protocol.

The benchmark code is located at `usr/init/src/vmops/`. To invoke the
benchmarks, run:

```bash
RUST_TEST_THREADS=1 cargo test --test s10* -- s10_vmops_benchmark --nocapture
RUST_TEST_THREADS=1 cargo test --test s10* -- s10_vmops_latency_benchmark --nocapture
RUST_TEST_THREADS=1 cargo test --test s10* -- s10_vmops_unmaplat_latency_benchmark --nocapture
RUST_TEST_THREADS=1 cargo test --test s10* -- s10_shootdown_simple --nocapture
```

## Network

TBD.
