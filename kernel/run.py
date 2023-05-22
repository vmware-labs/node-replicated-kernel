#!/usr/bin/python3

# Copyright © 2021 VMware, Inc. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR MIT

import argparse
import os
import sys
import pathlib
import shutil
import subprocess
import prctl
import signal
import toml
import pexpect
import plumbum
import re
import errno
from time import sleep
import tempfile

from plumbum import colors, local, SshMachine
from plumbum.commands import ProcessExecutionError

from plumbum.cmd import whoami, python3, cat, getent, whoami, cargo


def exception_handler(exception_type, exception, traceback):
    print("%s: %s" % (exception_type.__name__, exception))


#
# run.py script settings
#
SCRIPT_PATH = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
CARGO_DEFAULT_ARGS = ["--color", "always"]
CARGO_NOSTD_BUILD_ARGS = ["-Z", "build-std=core,alloc",
                          "-Z", "build-std-features=compiler-builtins-mem"]
ARCH = "x86_64"

IVSHMEM_DEVICE_ADDR = 6

def get_network_config(workers):
    """
    Returns a list of network configurations for the workers.
    """
    config = {}
    for i in range(workers):
        config['tap{}'.format(2*i)] = {
            'mid': i,
            'mac': '56:b4:44:e9:62:d{:x}'.format(i),
        }
    return config


MAX_WORKERS = 16
NETWORK_CONFIG = get_network_config(MAX_WORKERS)
NETWORK_INFRA_IP = '172.31.0.20/24'

DCM_SCHEDULER_VERSION = "1.1.10"

#
# Important globals
#
BOOTLOADER_PATH = (SCRIPT_PATH / '..').resolve() / 'bootloader'
TARGET_PATH = (SCRIPT_PATH / '..').resolve() / 'target'
KERNEL_PATH = SCRIPT_PATH
LIBS_PATH = (SCRIPT_PATH / '..').resolve() / 'lib'
USR_PATH = (SCRIPT_PATH / '..').resolve() / 'usr'

UEFI_TARGET = "{}-uefi".format(ARCH)
KERNEL_TARGET = "{}-nrk".format(ARCH)
USER_TARGET = "{}-nrk-none".format(ARCH)
USER_RUSTFLAGS = "-Clink-arg=-zmax-page-size=0x200000"

#
# Command line argument parser
#
parser = argparse.ArgumentParser()
# General build arguments
parser.add_argument("-v", "--verbose", action="store_true",
                    help="increase output verbosity")

parser.add_argument("-r", "--release", action="store_true",
                    help="Do a release build.")
parser.add_argument("--kfeatures", type=str, nargs='+', default=[],
                    help="Cargo features to enable (in the kernel).")
parser.add_argument("--no-kfeatures", action="store_true", default=False,
                    help="Disable default Cargo features (in the kernel).", required=False)
parser.add_argument("--ufeatures", type=str, nargs='+', default=[],
                    help="Cargo features to enable (in user-space, use module_name:feature_name syntax to specify module specific features, e.g. init:print-test).")
parser.add_argument('-m', '--mods', nargs='+', default=['init'],
                    help='User-space modules to be included in build & deployment', required=False)
parser.add_argument("--cmd", type=str,
                    help="Command line arguments passed to the kernel.")
parser.add_argument("--machine",
                    help='Which machine to run on (defaults to qemu)', required=False, default='qemu')

parser_tasks_mut = parser.add_mutually_exclusive_group(required=False)
parser_tasks_mut.add_argument("-n", "--norun", action="store_true", default=False,
                    help="Only build, don't run")
parser_tasks_mut.add_argument("-b", "--nobuild", action="store_true", default=False,
                    help="Only run, don't build")


# DCM Scheduler arguments
parser.add_argument("--dcm-path",
                    help='Path of DCM jar to use (defaults to latest release)', required=False, default=None)

# QEMU related arguments
parser.add_argument("--qemu-nodes", type=int,
                    help="How many NUMA nodes and sockets (for qemu).", required=False, default=None)
parser.add_argument("--qemu-cores", type=int,
                    help="How many cores (will get evenly divided among nodes).", default=1)
parser.add_argument("--qemu-memory", type=int,
                    help="How much total memory in MiB (will get evenly divided among nodes).", default=1024)
parser.add_argument("--qemu-pmem", type=int,
                    help="How much total peristent memory in MiB (will get evenly divided among nodes).", required=False, default=0)
parser.add_argument("--qemu-affinity", action="store_true", default=False,
                    help="Pin QEMU instance to dedicated host cores.")
parser.add_argument("--qemu-prealloc", action="store_true", default=False,
                    help="Pre-alloc memory for the guest", required=False)
parser.add_argument("--qemu-large-pages", action="store_true", default=False,
                    help="Use large-pages on the host for guest memory", required=False)
parser.add_argument("--qemu-settings", type=str,
                    help="Pass additional generic QEMU arguments.")
parser.add_argument("--qemu-monitor", action="store_true",
                    help="Launch the QEMU monitor (for qemu)")
parser.add_argument("--pvrdma", action="store_true",
                    help="Add para-virtual RDMA device (for qemu)", default=False)
parser.add_argument("-d", "--qemu-debug-cpu", action="store_true",
                    help="Debug CPU reset (for qemu)")
parser.add_argument('--nic', default='e1000', choices=["e1000", "virtio-net-pci", "vmxnet3"],
                    help='What NIC model to use for emulation', required=False)
parser.add_argument('--tap', default='tap0', choices=[f"tap{2*i}" for i in range(MAX_WORKERS)],
                    help='Which tap interface to use from the host', required=False)
parser.add_argument('--kgdb', action="store_true",
                    help="Use the GDB remote debugger to connect to the kernel")
parser.add_argument('--qemu-ivshmem',
                    type=int,
                    help="Enable the ivshmem device with the size in MiB.",
                    required=False,
                    default=0)
parser.add_argument('--qemu-shmem-path',
                    type=str,
                    help="Provide shared memory file path.",
                    required=False,
                    default="")

# Baremetal argument
parser.add_argument('--configure-ipxe', action="store_true", default=False,
                    help='Execute pre-boot setup for bare-metal booting.', required=False)
parser.add_argument('--no-reboot', action="store_true", default=False,
                    help='Do not initiate a machine reboot.', required=False)

subparser = parser.add_subparsers(help='Advanced network configuration')

# Network setup parser
parser_net = subparser.add_parser('net', help='Network setup')
parser_net.add_argument('--workers', type=int, required=False, default=0,
                        help='Setup `n` workers connected to one controller.')

parser_net_mut = parser_net.add_mutually_exclusive_group(required=False)
parser_net_mut.add_argument("--network-only", action="store_true", default=False,
                            help="Setup network only.")
parser_net_mut.add_argument("--no-network-setup", action="store_true", default=False,
                            help="Setup network.")

NRK_EXIT_CODES = {
    0: "[SUCCESS]",
    1: "[FAIL] ReturnFromMain: main() function returned to arch_indepdendent part.",
    2: "[FAIL] Encountered kernel panic.",
    3: "[FAIL] Encountered OOM.",
    4: "[FAIL] Encountered unexpected Interrupt.",
    5: "[FAIL] General Protection Fault.",
    6: "[FAIL] Unexpected Page Fault.",
    7: "[FAIL] Unexpected process exit code when running a user-space test.",
    8: "[FAIL] Unexpected exception during kernel initialization.",
    9: "[FAIL] Got unrecoverable error (machine check, double fault)."
}


def log(msg):
    print(colors.bold | ">>>", end=" "),
    print(colors.bold.reset & colors.info | msg)


def build_bootloader(args):
    "Builds the bootloader, copies the binary in the target UEFI directory"
    log("Build bootloader")
    uefi_build_args = ['build', '--target', UEFI_TARGET]
    uefi_build_args += ['--package', 'bootloader']
    uefi_build_args += CARGO_DEFAULT_ARGS
    uefi_build_args += CARGO_NOSTD_BUILD_ARGS

    with local.cwd(BOOTLOADER_PATH):
        with local.env(RUST_TARGET_PATH=BOOTLOADER_PATH.absolute()):
            if args.verbose:
                print("cd {}".format(BOOTLOADER_PATH))
                print("RUST_TARGET_PATH={} cargo ".format(
                    BOOTLOADER_PATH.absolute()) + " ".join(uefi_build_args))
            cargo(*uefi_build_args)


def build_kernel(args):
    "Builds the kernel binary"
    log("Build kernel")
    with local.cwd(KERNEL_PATH):
        with local.env(RUST_TARGET_PATH=(KERNEL_PATH / 'src' / 'arch' / ARCH).absolute()):
            # TODO(cross-compilation): in case we use a cross compiler/linker
            # also set: CARGO_TARGET_X86_64_NRK_LINKER=x86_64-elf-ld
            build_args = ['build', '--target', KERNEL_TARGET]
            if args.no_kfeatures:
                build_args += ["--no-default-features"]
            for feature in args.kfeatures:
                build_args += ['--features', feature]
            build_args += CARGO_DEFAULT_ARGS
            build_args += CARGO_NOSTD_BUILD_ARGS
            if args.verbose:
                print("cd {}".format(KERNEL_PATH))
                print("RUST_TARGET_PATH={} cargo ".format(
                    KERNEL_PATH / 'src' / 'arch' / ARCH) + " ".join(build_args))
            cargo(*build_args)


def build_user_libraries(args):
    "Builds nrk vibrio lib to provide runtime support for other rump based apps"
    log("Build user-space lib vibrio")
    build_args = ['build', '--target', USER_TARGET]
    build_args += ["--features", "rumprt"]
    if args.nic == "virtio-net-pci":
        build_args += ["--features", "virtio"]
    # else: use e1000 / wm0
    build_args += CARGO_DEFAULT_ARGS
    build_args += CARGO_NOSTD_BUILD_ARGS

    # Make sure we build a static (.a) vibrio library
    # For linking with rumpkernel
    with local.cwd(LIBS_PATH / "vibrio"):
        with local.env(RUSTFLAGS=USER_RUSTFLAGS):
            with local.env(RUST_TARGET_PATH=USR_PATH.absolute()):
                if args.verbose:
                    print("cd {}".format(LIBS_PATH / "vibrio"))
                    print("RUSTFLAGS={} RUST_TARGET_PATH={} cargo ".format(USER_RUSTFLAGS,
                                                                           USR_PATH.absolute()) + " ".join(build_args))
                cargo(*build_args)


def build_userspace(args):
    "Builds user-space programs"
    build_args_default = ['build', '--target', USER_TARGET]
    build_args_default += CARGO_DEFAULT_ARGS
    build_args_default += CARGO_NOSTD_BUILD_ARGS

    for module in args.mods:
        if not (USR_PATH / module).exists():
            log("User module {} not found, skipping.".format(module))
            continue
        with local.cwd(USR_PATH / module):
            with local.env(RUSTFLAGS=USER_RUSTFLAGS):
                with local.env(RUST_TARGET_PATH=USR_PATH.absolute()):
                    build_args = build_args_default.copy()
                    for feature in args.ufeatures:
                        if ':' in feature:
                            mod_part, feature_part = feature.split(':')
                            if module == mod_part:
                                build_args += ['--features', feature_part]
                        else:
                            build_args += ['--features', feature]
                    log("Build user-module {}".format(module))
                    if args.verbose:
                        print("cd {}".format(USR_PATH / module))
                        print("RUSTFLAGS={} RUST_TARGET_PATH={} cargo ".format(
                            USER_RUSTFLAGS, USR_PATH.absolute()) + " ".join(build_args))
                    cargo(*build_args)


def deploy(args):
    """
    Deploys everything that got built to the UEFI ESP directory
    Also builds a disk image (.img file)
    """
    log("Deploy binaries")

    is_client = args.cmd and args.cmd.find("client") != -1
    is_controller = args.cmd and args.cmd.find("controller") != -1

    if is_controller or is_client:
        assert args.workers - 1 > 0, "Need at least one worker"

    # Clean up / create ESP dir structure
    debug_release = 'release' if args.release else 'debug'
    uefi_build_path = TARGET_PATH / UEFI_TARGET / debug_release
    user_build_path = TARGET_PATH / USER_TARGET / debug_release
    kernel_build_path = TARGET_PATH / KERNEL_TARGET / debug_release

    # Clean and create_esp dir:
    esp_path = uefi_build_path / 'esp'
    if (esp_path.exists() != True) or (esp_path.exists() and is_client != True):
        if esp_path.exists() and esp_path.is_dir():
            shutil.rmtree(esp_path, ignore_errors=False)
        esp_boot_path = esp_path / "EFI" / "Boot"
        esp_boot_path.mkdir(parents=True, exist_ok=True)

        # Deploy bootloader
        shutil.copy2(kernel_build_path / 'nrk', os.getcwd())
        shutil.copy2(kernel_build_path / 'nrk', esp_path / 'kernel')

        # Deploy kernel
        shutil.copy2(uefi_build_path / 'bootloader.efi',
                     esp_boot_path / 'BootX64.efi')

    # Append globally unique machine id to cmd (for rackscale)
    # as well as a number of workers (clients)
    if args.cmd and NETWORK_CONFIG[args.tap]['mid'] != None:
        args.cmd += " mid={}".format(NETWORK_CONFIG[args.tap]['mid'])
        if is_controller or is_client:
            args.cmd += " workers={}".format(args.workers)
    # Write kernel cmd-line file in ESP dir
    with open(esp_path / 'cmdline.in', 'w') as cmdfile:
        if args.cmd:
            cmdfile.write('./kernel {}'.format(args.cmd))
        else:
            cmdfile.write('./kernel')

    deployed = []
    # Deploy user-modules
    for module in args.mods:
        if not (user_build_path / module).is_file():
            log("[WARN] Module not found: {}".format(module))
            continue
        if module != "rkapps":
            shutil.copy2(user_build_path / module, esp_path)
            deployed.append(module)
        else:
            # TODO(ugly): Special handling of the rkapps module
            # (they end up being built as multiple .bin binaries)
            to_copy = [app for app in user_build_path.glob(
                "*.bin") if app.is_file()]
            deployed.extend([f.name for f in to_copy])
            for app in to_copy:
                shutil.copy2(app, esp_path)

    # Write kernel cmd-line file in ESP dir
    with open(esp_path / 'boot.php', 'w') as boot_file:
        ipxe_script = """#!ipxe
imgfetch EFI/Boot/BootX64.efi
imgfetch kernel
imgfetch cmdline.in
{}
boot EFI/Boot/BootX64.efi
""".format('\n'.join(['imgfetch {}'.format(m) for m in deployed]))

        boot_file.write(ipxe_script)


def run_qemu(args):
    """
    Run the kernel on a QEMU instance.
    """

    from plumbum.cmd import sudo, corealloc
    from plumbum.machines import LocalCommand
    from packaging import version

    if args.qemu_pmem:
        required_version = version.parse("6.0.0")
        version_check = ['/usr/bin/env'] + \
            ['qemu-system-x86_64'] + ['-version']
        # TODO: Ad-hoc approach to find version number. Can we improve it?
        ver = str(subprocess.check_output(version_check)
                  ).split(' ')[3].split('\\n')[0]
        if version.parse(ver) < required_version:
            print("Update Qemu to version {} or higher".format(required_version))
            sys.exit(errno.EACCES)

    log("Starting QEMU")
    debug_release = 'release' if args.release else 'debug'
    esp_path = TARGET_PATH / UEFI_TARGET / debug_release / 'esp'

    qemu_default_args = ['-no-reboot']
    # Setup KVM and required guest hardware features
    qemu_default_args += ['-enable-kvm']
    qemu_default_args += ['-cpu',
                          'host,migratable=no,+invtsc,+tsc,+x2apic,+fsgsbase']
    # Use serial communication
    # '-nographic',
    qemu_default_args += ['-display', 'none', '-serial', 'stdio']

    if args.kgdb:
        # Add a second serial line (VM I/O port 0x2f8 <-> localhost:1234) that
        # we use to connect with gdb
        qemu_default_args += ['-serial', 'tcp:127.0.0.1:1234,server,nowait']

    # Add UEFI bootloader support
    qemu_default_args += ['-drive',
                          'if=pflash,format=raw,file={}/OVMF_CODE.fd,readonly=on'.format(BOOTLOADER_PATH)]
    qemu_default_args += ['-drive',
                          'if=pflash,format=raw,file={}/OVMF_VARS.fd,readonly=on'.format(BOOTLOADER_PATH)]
    qemu_default_args += ['-device', 'ahci,id=ahci,multifunction=on']
    qemu_default_args += ['-drive',
                          'if=none,format=raw,file=fat:rw:{},id=esp'.format(esp_path)]
    qemu_default_args += ['-device', 'ide-hd,bus=ahci.0,drive=esp']

    # Debug port to exit qemu and communicate back exit-code for tests
    qemu_default_args += ['-device',
                          'isa-debug-exit,iobase=0xf4,iosize=0x04']

    if args.qemu_ivshmem:
        # If you change the the device addr, you must change it in vibrio::rumprt::dev
        qemu_default_args += ['-device', 'ivshmem-doorbell,vectors=3,chardev=id,addr={}'.format(IVSHMEM_DEVICE_ADDR)]
        qemu_default_args += [
            '-chardev',
            'socket,path={},id=id'.format(args.qemu_shmem_path)
        ]

    # Enable networking:
    mac, tap = NETWORK_CONFIG[args.tap]['mac'], args.tap
    qemu_default_args += ['-device',
                          '{},netdev=n1,mac={}'.format(args.nic, mac)]
    qemu_default_args += ['-netdev',
                          'tap,id=n1,script=no,ifname={}'.format(tap)]

    def numa_nodes_to_list(file):
        nodes = []
        good_nodes = cat[file]().split(',')
        for node_range in good_nodes:
            if "-" in node_range:
                nlow, nmax = node_range.split('-')
                for i in range(int(nlow), int(nmax)+1):
                    nodes.append(i)
            else:
                nodes.append(int(node_range.strip()))
        return nodes

    def query_host_numa():
        mem_nodes = numa_nodes_to_list(
            "/sys/devices/system/node/has_memory")
        cpu_nodes = numa_nodes_to_list("/sys/devices/system/node/has_cpu")

        # Now return the intersection of the two
        return list(sorted(set(mem_nodes).intersection(set(cpu_nodes))))

    host_numa_nodes_list = query_host_numa()
    num_host_numa_nodes = len(host_numa_nodes_list)
    if args.qemu_nodes and args.qemu_nodes > 0:
        for node in range(0, args.qemu_nodes):
            if args.qemu_cores > 1:
                mem_per_node = args.qemu_memory / args.qemu_nodes
                prealloc = "on" if args.qemu_prealloc else "off"
                large_pages = ",hugetlb=on,hugetlbsize=2M" if args.qemu_large_pages else ""
                backend = "memory-backend-ram" if not args.qemu_large_pages else "memory-backend-memfd"
                # This is untested, not sure it works
                # assert args.pvrdma and not args.qemu_default_args
                qemu_default_args += ['-object', '{},id=nmem{},merge=off,dump=on,prealloc={},size={}M,host-nodes={},policy=bind{},share=on'.format(
                    backend, node, prealloc, int(mem_per_node), 0 if num_host_numa_nodes == 0 else host_numa_nodes_list[node % num_host_numa_nodes], large_pages)]

                qemu_default_args += ['-numa',
                                      "node,memdev=nmem{},nodeid={}".format(node, node)]
                qemu_default_args += ["-numa", "cpu,node-id={},socket-id={}".format(
                    node, node)]

            # NVDIMM related arguments
            if args.qemu_cores > 0 and args.qemu_pmem:
                pmem_per_node = args.qemu_pmem / args.qemu_nodes
                default = "/mnt/node{}".format(node)
                if os.path.isdir(default):
                    qemu_default_args += ['-object', 'memory-backend-file,id=pmem{},mem-path={},size={}M,pmem=on,share=on'.format(
                        node, default, int(pmem_per_node))]
                else:
                    with tempfile.NamedTemporaryFile() as tmp:
                        qemu_default_args += ['-object', 'memory-backend-file,id=pmem{},mem-path={},size={}M,pmem=off,share=on'.format(
                            node, tmp.name, int(pmem_per_node))]
                qemu_default_args += ['-device',
                                      'nvdimm,node={},slot={},id=nvdimm{},memdev=pmem{}'.format(node, node, node, node)]

    if args.qemu_cores and args.qemu_cores > 1 and args.qemu_nodes:
        qemu_default_args += ["-smp", "{},sockets={},maxcpus={}".format(
            args.qemu_cores, args.qemu_nodes, args.qemu_cores)]
    else:
        qemu_default_args += ["-smp",
                              "{},sockets=1".format(args.qemu_cores)]

    if args.qemu_nodes and args.qemu_memory and args.qemu_pmem:
        qemu_default_args += ['-M', 'nvdimm=on,nvdimm-persistence=cpu']
        qemu_default_args += ['-m', '{},slots={},maxmem={}M'.format(
            str(args.qemu_memory), args.qemu_nodes, args.qemu_memory + args.qemu_pmem)]
    elif args.qemu_memory:
        qemu_default_args += ['-m', str(args.qemu_memory)]
    if args.pvrdma:
        # ip link add bridge1 type bridge ; ifconfig bridge1 up
        # TODO: mac address depend or exokernel or no?
        qemu_default_args += ['-netdev', 'bridge,id=bridge1',
                              '-device', 'vmxnet3,netdev=bridge1,mac=56:b4:44:e9:62:d0,addr=10.0,multifunction=on']
        qemu_default_args += ['-chardev', 'socket,path=/var/run/rdmacm-mux-mlx5_0-0,id=mads',
                              '-device', 'pvrdma,ibdev=mlx5_0,ibport=0,netdev=enp216s0f0,mad-chardev=mads,addr=10.1']
    if args.qemu_debug_cpu:
        qemu_default_args += ['-d', 'int,cpu_reset']
    if args.qemu_monitor:
        qemu_default_args += ['-monitor',
                              'telnet:127.0.0.1:55555,server,nowait']

    # Name threads on host for `qemu_affinity.py` to find it
    qemu_default_args += ['-name', 'nrk,debug-threads=on']

    qemu_args = ['qemu-system-x86_64'] + qemu_default_args.copy()
    if args.qemu_settings:
        qemu_args += args.qemu_settings.split()

    # Run a QEMU instance
    cmd = ['/usr/bin/env'] + qemu_args
    if args.verbose:
        print(' '.join(cmd))

    # Spawn qemu first, then set the guest CPU affinities
    # The `preexec_fn` ensures that qemu dies if run.py exits
    execution = subprocess.Popen(
        cmd, stderr=None, stdout=None, env=os.environ.copy(), preexec_fn=lambda: prctl.set_pdeathsig(signal.SIGKILL))

    LocalCommand.QUOTE_LEVEL = 3

    if args.qemu_cores and args.qemu_affinity:
        affinity_list = str(corealloc['-c',
                                      str(args.qemu_cores), '-t', 'interleave']()).strip()
        # For big machines it can take a while to spawn all threads in qemu
        # if but if the threads are not spawned qemu_affinity.py fails, so we sleep
        sleep(2.00)
        if args.verbose:
            log("QEMU affinity {}".format(affinity_list))

        iteration = 0
        while True:
            try:
                sudo[python3['./qemu_affinity.py',
                             '-k', affinity_list.split(' '), '--', str(execution.pid)]]()
            except ProcessExecutionError as e:
                if args.qemu_prealloc or args.qemu_large_pages:
                    iteration += 1
                    sleep(2.00)
                    if iteration > 20 and iteration % 10 == 0:
                        log("Still waiting for Qemu to preallocate memory...")
                    continue
                else:
                    raise
            break

    # Wait until qemu exits
    execution.wait()

    nrk_exit_code = execution.returncode >> 1
    if NRK_EXIT_CODES.get(nrk_exit_code):
        print(NRK_EXIT_CODES[nrk_exit_code])
    else:
        print(
            "[FAIL] Kernel exited with unknown error status {}... Update the script!".format(nrk_exit_code))

    if nrk_exit_code != 0:
        log("Invocation was: {}".format(cmd))
        if execution.stderr:
            print("STDERR: {}".format(execution.stderr.decode('utf-8')))

    return nrk_exit_code


def detect_baremetal_shutdown(lb):
    if "[shutdown-request]" in lb:
        parts = [p.strip() for p in re.split(' |\r\n', lb)]
        if len(parts) < 2:
            return None
        else:
            idx = parts.index("[shutdown-request]")
            if len(parts) > idx + 1:
                exit_value = int(parts[idx+1])
            else:
                raise Exception("Didn't read enough for exit code XD")
            if exit_value in NRK_EXIT_CODES:
                print(NRK_EXIT_CODES[exit_value])
            return exit_value
    else:
        return None


def run_baremetal(args):

    # Need to find a config file ${args.machine}.toml
    cfg_file = SCRIPT_PATH / "{}.toml".format(args.machine)
    if not cfg_file.exists():
        log("Machine {} not supported, '{}' not found.".format(
            args.machine, cfg_file))
        return 99
    else:
        cfg = toml.load(cfg_file.open())
        log("Booting on bare-metal server {}".format(
            cfg['server']['name']))

        if args.configure_ipxe:
            log("Execute pre-boot: {}".format(
                cfg['server']['pre-boot-cmd']))
            subprocess.run(cfg['server']['pre-boot-cmd'],
                           shell=True, check=True, timeout=10)

        log("Deploying binaries to ipxe location")
        debug_release = 'release' if args.release else 'debug'
        uefi_build_path = TARGET_PATH / UEFI_TARGET / debug_release

        esp_path = uefi_build_path / 'esp'
        to_copy = [plumbum.local.path(entry) for entry in esp_path.glob("*")]
        deploy = SshMachine(cfg['deploy']['hostname'],
                            user=cfg['deploy']['username'], keyfile=cfg['deploy']['ssh-pubkey'])
        dest = deploy.path(cfg['deploy']['ipxe-deploy'])
        plumbum.path.utils.copy(to_copy, dest)

        ssh_cmd = "sshpass -p'{}' ssh {}@{}".format(
            cfg['idrac']['password'], cfg['idrac']['username'], cfg['idrac']['hostname'])
        idrac = pexpect.spawn(ssh_cmd)

        idx = idrac.expect(['/admin1-> ', 'racadm>>'])
        if idx == 0:
            # Go to system1, so we can reboot it
            idrac.sendline('cd system1')
            idrac.expect('/admin1/system1')
        else:
            # We are in some racadm shell (on some machines), thanks for the
            # inconsistency, iDRAC
            pass

        # power-cycle it:
        if not args.no_reboot:
            log("Rebooting machine...")
            idrac.sendline('racadm serveraction powercycle')
            idrac.expect('Server power operation initiated successfully')

        # Connect to system console, and read it out:
        log("Connection to console...")
        idrac.sendline('console {}'.format(cfg['idrac']['console']))
        timeout = 1
        linebuffer = ""
        while True:
            try:
                read = idrac.read_nonblocking(
                    size=1024, timeout=timeout)
                timeout = 1

                # We want to use non-blocking read so we can abort
                # in case we're stuck, unfortunately there is no
                # non-blocking readline, so we have to do a simple
                # line buffer:
                if b'\r\n' in read:
                    splitted_read = list(read.decode('utf-8').split('\r\n'))
                    # Print current line, add stuff previously read
                    linebuffer = linebuffer + splitted_read[0]
                    print("{}".format(linebuffer))
                    ret = detect_baremetal_shutdown(linebuffer)
                    if ret is not None:
                        sys.exit(ret)

                    # In case we have some more complete lines, print:
                    for line in splitted_read[1:-1]:
                        print("{}".format(line))
                        ret = detect_baremetal_shutdown(line)
                        if ret is not None:
                            sys.exit(ret)

                    # The last element will be the beginning of the next line or an empty string
                    linebuffer = splitted_read[-1]
                else:
                    linebuffer += read.decode('utf-8')
            except pexpect.exceptions.TIMEOUT as e:
                print(linebuffer, end='')
                ret = detect_baremetal_shutdown(linebuffer)
                if ret is not None:
                    sys.exit(ret)

                linebuffer = ''
                if timeout == 1:
                    timeout = cfg['idrac']['boot-timeout']
                    # Now, wait till boot timeout and see if we really don't get anything
                    continue
                else:
                    print('')
                    raise e
            except KeyboardInterrupt:
                print(linebuffer)
                sys.exit()
        idrac.close()


def run(args):
    """
    Run the system on a hardware/emulation platform
    Returns: A nrk exit error code.
    """

    if args.machine == 'qemu':
        return run_qemu(args)
    else:
        return run_baremetal(args)


def configure_network(args):
    """
    Configure the host network stack to allow host/cross VM communication.
    """
    from plumbum.cmd import sudo, tunctl, ifconfig, ip, brctl

    user = (whoami)().strip()
    group = (local['id']['-gn'])().strip()

    # TODO: Could probably avoid 'sudo' here by doing
    # sudo setcap cap_net_admin .../run.py
    # in the setup.sh script

    # Remove any existing interfaces
    sudo[ip[['link', 'set', 'br0', 'down']]](retcode=(0, 1))
    sudo[brctl[['delbr', 'br0']]](retcode=(0, 1))
    for tap in NETWORK_CONFIG:
        sudo[ip[['link', 'set', '{}'.format(tap), 'down']]](retcode=(0, 1))
        sudo[ip[['link', 'del', '{}'.format(tap)]]](retcode=(0, 1))

    # Need to find out how to set default=True in case workers are >0 in `args`
    if (not 'workers' in args) or ('workers' in args and args.workers <= 1):
        sudo[tunctl[['-t', args.tap, '-u', user, '-g', group]]]()
        sudo[ifconfig[args.tap, NETWORK_INFRA_IP]]()
        sudo[ip[['link', 'set', args.tap, 'up']]](retcode=(0, 1))
    else:
        assert args.workers <= MAX_WORKERS, "Too many workers, can't configure network"
        sudo[ip[['link', 'add', 'br0', 'type', 'bridge']]]()
        sudo[ip[['addr', 'add', NETWORK_INFRA_IP, 'brd', '+', 'dev', 'br0']]]()
        for _, ncfg in zip(range(0, args.workers), NETWORK_CONFIG):
            sudo[tunctl[['-t', ncfg, '-u', user, '-g', group]]]()
            sudo[ip[['link', 'set', ncfg, 'up']]](retcode=(0, 1))
            sudo[brctl[['addif', 'br0', ncfg]]]()
        sudo[ip[['link', 'set', 'br0', 'up']]](retcode=(0, 1))


def configure_dcm_scheduler(args):
    """
    Set up the DCM jar, fetch if configured version isn't present
    """
    jar_dir = "../target"
    jar_name = "dcm-scheduler.jar"
    symlink_jar_path = os.path.join(jar_dir, jar_name)

    # Use set jar path (allows for local development) if given in argument
    dcm_path = args.dcm_path

    # If not given in argument, use specific version of DCM jar
    if args.dcm_path == None:
        dcm_jar = "scheduler-{}-jar-with-dependencies.jar".format(
            DCM_SCHEDULER_VERSION)
        dcm_path = os.path.join(jar_dir, dcm_jar)

        # Download jar if necessary
        if not os.path.exists(dcm_path):
            subprocess.run("wget https://github.com/hunhoffe/nrk-dcm-scheduler/releases/download/release-{}/{} -P {}".format(
                DCM_SCHEDULER_VERSION, dcm_jar, jar_dir), shell=True, check=True, timeout=10)

    # Create consistent symlink location for the DCM scheduler jar
    if os.path.exists(symlink_jar_path) or os.path.islink(symlink_jar_path):
        os.unlink(symlink_jar_path)
    os.symlink(dcm_path, symlink_jar_path)


#
# Main routine of run.py
#
if __name__ == '__main__':
    "Execution pipeline for building and launching nrk"
    args = parser.parse_args()

    # Setup network
    if not ('no_network_setup' in args and args.no_network_setup):
        configure_network(args)

    if 'network_only' in args and args.network_only:
        sys.exit(0)

    user = whoami().strip()
    kvm_members = getent['group', 'kvm']().strip().split(":")[-1].split(',')
    if not user in kvm_members and not args.norun:
        print("Your user ({}) is not in the kvm group.".format(user))
        print("Add yourself to the group with `sudo adduser {} kvm`".format(user))
        print("You'll likely have to restart for changes to take effect,")
        print("or run `sudo chmod +666 /dev/kvm` if you don't care about")
        print("kvm access restriction on the machine.")
        sys.exit(errno.EACCES)

    if 'gdb' in args.kfeatures and not args.kgdb:
        print("You set gdb in kfeatures but haven't provided `--kgdb` to `run.py`.")
        print("Just use `--kgdb` to make sure `run.py` configures QEMU with the proper serial line.")
        sys.exit(errno.EINVAL)

    try:
        from plumbum.cmd import sudo
        r = sudo['-n']['true']()
    except ProcessExecutionError as e:
        if e.retcode == 1:
            print("`sudo` is asking for a password, but for testing to work, `sudo` should not prompt for a password.")
            print("Add the line `{} ALL=(ALL) NOPASSWD: ALL` with the `sudo visudo` command to fix this.".format(user))
            sys.exit(errno.EINVAL)
        else:
            raise e

    # Setup DCM scheduler jar
    configure_dcm_scheduler(args)

    if args.release:
        CARGO_DEFAULT_ARGS.append("--release")
    if args.verbose:
        CARGO_DEFAULT_ARGS.append("--verbose")
    else:
        # Minimize python exception backtraces
        sys.excepthook = exception_handler

    if not args.nobuild:
        # Build
        build_bootloader(args)
        build_kernel(args)
        build_user_libraries(args)
        build_userspace(args)

    # Deploy
    deploy(args)

    # Run
    if not args.norun:
        r = run(args)
        sys.exit(r)
