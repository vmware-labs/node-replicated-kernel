# Testing

If you've found and fixed a bug, we better write a test for it. nrk uses
several test-frameworks and methodologies to ensure everything works as
expected:

- Regular unit tests: Those can be executed running `cargo test` in the project
  folder. Sometimes adding `RUST_TEST_THREADS=1` is necessary due to the
  structure of the runner/frameworks used. This should be indicated in the
  individual READMEs.
- A slightly more exhaustive variant of unit tests is property based testing. We
  use [proptest](https://github.com/altsysrq/proptest) to make sure that the
  implementation of kernel sub-systems corresponds to a reference model
  implementation.
- Integration tests are found in the kernel, they typically launch a qemu
  instance and use [rexpect](https://github.com/philippkeller/rexpect) to
  interact with the guest.
- Fuzz testing: TBD.

## Running tests

To run the unit tests of the kernel:

1. `cd kernel`
1. `RUST_BACKTRACE=1 RUST_TEST_THREADS=1 cargo test --bin nrk`

To run the integration tests of the kernel:

1. `cd kernel`
1. `RUST_TEST_THREADS=1 cargo test --test '*'`

If you would like to run a specific integration test you can pass it with `--`:

1. `RUST_TEST_THREADS=1 cargo test --test '*' -- userspace_smoke`

If you would like to run a specific set of integration tests, you can specify the file name with `--test`:

1. `RUST_TEST_THREADS=1 cargo test --test s00_core_test`

In case an integration test fails, adding `--nocapture` at the end (needs to
come after the `--`) will make sure that the underlying `run.py` invocations are
printed to the stdout. This can be helpful to figure out the exact `run.py`
invocation that a test is doing so you can invoke it yourself manually for
debugging.

> Parallel testing for he kernel is not possible at the moment due to reliance
> on build flags for testing.

The commitable.sh script automatically runs the unit and integration tests:

```bash
cd kernel
bash commitable.sh
```

## Writing a unit-test for the kernel

Typically these can just be declared in the code using `#[test]`. Note that
tests by default will run under the `unix` platform. A small hack is necessary
to allow tests in the `x86_64` to compile and run under unix too: When run on a
x86-64 unix platform, the platform specific code of the kernel in `arch/x86_64/`
will be included as a module named `x86_64_arch` whereas normally it would be
`arch`. This is a double-edged sword: we can now write tests that test the
actual bare-metal code (great), but we can also easily crash the test process by
calling an API that writes an MSR for example (e.g, things that would require
ring 0 priviledge level).

## Writing an integration test for the kernel

Integration tests typically spawns a QEMU instance and beforehand compiles the
kernel/user-space with a custom set of Cargo feature flags. Then it parses the
qemu output to see if it gave the expected output. Part of those custom compile
flags will also choose a different main() function than the one you're seeing
(which will go off to load and schedule user-space programs for example).

There is two parts to the integration test.

- The host side (that will go off and spawn a qemu instance) for running the
  integration tests. It is found in `kernel/tests`.
- The corresponding main functions in the kernel that gets executed for a
  particular example are located at `kernel/src/integration_main.rs`

To add a new integration test the following tests may be necessary:

1. Modify `kernel/Cargo.toml` to add a feature (under `[features]`) for the test
   name.
1. Optional: Add a new `xmain` function and test implementation in it to
   `kernel/src/integration_main.rs` with the used feature name as an annotation.
   It may also be possible to re-use an existing xmain function, in that case
   make not of the feature name used to include it.
1. Add a runner function to one of the files in `kernel/tests` that builds the
   kernel with the cargo feature runs it and checks the output.

Integration tests are divided into categories and named accordingly (partially
to ensure the tests run in a sensible order):
* ```s00_*```: Core kernel functionality like boot-up and fault handling
* ```s01_*```: Low level kernel services: SSE, memory allocation etc.
* ```s02_*```: High level kernel services: ACPI, core booting mechanism, NR, VSpace etc.
* ```s03_*```: High level kernel functionality: Spawn cores, run user-space programs
* ```s04_*```: User-space runtimes
* ```s05_*```: User-space applications
* ```s06_*```: Rackscale (distributed) tests

Benchmarks are named as such: 
* ```s10_*```: User-space applications benchmarks
* ```s11_*```: Rackscale (distributed) benchmarks

The ```s11_*``` benchmarks may be configured with two features:
* ```baseline```: Runs NrOS configured similarly to rackscale, for comparison
* ```affinity-shmem```: Runs the ```ivshmem-server``` using shmem with NUMA affinity.
  This option requires preconfiguring hugetlbfs with
  ```sudo hugeadm --create-global-mounts```,
  having a kernel with 2MB huge pages enabled, and then also adding 1024 2MB pages per
  node, with a command like:
  ```echo <page-num> | sudo numactl -m <node-num> tee -a /proc/sys/vm/nr_hugepages_mempolicy```
  The number of huge pages per node may be verified with ```numastat -m```.
 
## Network

nrk has support for three network interfaces at the moment: virtio, e1000 and
vmxnet3. virtio and e1000 are available by using the respective rumpkernel
drivers (and it's network stack). vmxnet3 is a standalone implementation that
uses `smoltcp` for the network stack and is also capable of running in ring 0.

### Network Setup

The integration tests that run multiple instances of nrk require
bridged tap interfaces. For those integration tests, the test framework calls
run.py with the `--network-only` flag which will destroy existing conflicting
tap interfaces and create new tap interface(s) for the test based on the
number of hosts in the test. Then, to run the nrk instances, run.py is invoked
with the `--no-network-setup` flag.

To setup the network for a single client and server (`--workers clients+server`), run the following command:

```bash
python3 run.py --kfeatures integration-test --cmd "test=network_only" net --workers 2 --network-only
```

### Ping

A simple check is to use ping (on the host) to test the network stack
functionality and latency. Adaptive `ping -A`, flooding `ping -f` are good modes
to see that the low-level parts of the stack work and can handle an "infinite"
amount of packets.

Some expected output if it's working:

```log
$ ping 172.31.0.10
64 bytes from 172.31.0.10: icmp_seq=1 ttl=64 time=0.259 ms
64 bytes from 172.31.0.10: icmp_seq=2 ttl=64 time=0.245 ms
64 bytes from 172.31.0.10: icmp_seq=3 ttl=64 time=0.267 ms
64 bytes from 172.31.0.10: icmp_seq=4 ttl=64 time=0.200 ms
```

For network tests, it's easiest to start a DHCP server for the tap interface so
the VM receives an IP by communicating with the server:

```bash
# Stop apparmor from blocking a custom dhcp instance
service apparmor stop
# Terminate any (old) existing dhcp instance
sudo  killall dhcpd
# Spawn a dhcp server, in the kernel/ directory do:
sudo dhcpd -f -d tap0 --no-pid -cf ./tests/dhcpd.conf
```

A fully automated CI test that checks the network using ping is available as
well, it can be invoked with the following command:

```bash
RUST_TEST_THREADS=1 cargo test --test '*' -- s04_userspace_rumprt_net
```

### socat and netcat

`socat` is a helpful utility on the host to interface with the network, for
example to open a UDP port and print on incoming packets on the command line,
the following command can be used:

```bash
socat UDP-LISTEN:8889,fork stdout
```

Similarly we can use `netcat` to connect to a port and send a payload:

```bash
nc 172.31.0.10 6337
```

The integration tests `s05_redis_smoke` and `s04_userspace_rumprt_net` make use
of those tool to verify that networking is working as expected.

### tcpdump

tcpdump is another handy tool to see all packets that are exchanged on a given
interface etc. For debugging nrk network issues, this command is useful as it displays
all packets on `tap0`:

```bash
tcpdump -i tap0 -vvv -XX
```
