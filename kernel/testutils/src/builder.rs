// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::{io, process};

use hwloc2::{ObjectType, Topology};
use lazy_static::lazy_static;

/// Environment variable that points to machine config (for baremetal booting)
const BAREMETAL_MACHINE: &'static str = "BAREMETAL_MACHINE";

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    pub fn as_qemu_target(&self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64-qemu",
            Arch::Aarch64 => "aarch64-qemu",
        }
    }
}

/// Different machine types we can run on.
#[derive(Eq, PartialEq, Debug, Clone)]
pub enum Machine {
    /// A bare-metal machine identified by a string.
    /// The name is described in the corresponding TOML file.
    ///
    /// (e.g., Machine::BareMetal("b1542".into()) should have a corresponding b1542.toml file).
    Baremetal(Arch, String),
    /// Run on a virtual machine with QEMU (machine parameters determined by current host)
    Qemu(Arch),
}

impl Machine {
    pub fn determine() -> Self {
        let arch = match std::env::var("ARCH") {
            Ok(arch) => match arch.as_str() {
                "x86_64" => Arch::X86_64,
                "aarch64" => Arch::Aarch64,
                _ => panic!("Unknown architecture: {}", arch),
            },
            _ => {
                println!("ARCH not set, assuming x86_64");
                Arch::X86_64
            }
        };
        match std::env::var(BAREMETAL_MACHINE) {
            Ok(name) => {
                if name.is_empty() {
                    panic!("{} enviroment variable empty.", BAREMETAL_MACHINE);
                }
                if !Path::new(&name).exists() {
                    panic!(
                        "'{}.toml' file not found. Check {} enviroment variable.",
                        name, BAREMETAL_MACHINE
                    );
                }
                Machine::Baremetal(arch, name)
            }
            _ => Machine::Qemu(arch),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Machine::Qemu(Arch::X86_64) => "qemu-x86_64",
            Machine::Qemu(Arch::Aarch64) => "qemu-aarch64",
            Machine::Baremetal(_, s) => s.as_str(),
        }
    }

    pub fn arch(&self) -> Arch {
        match self {
            Machine::Qemu(arch) => *arch,
            Machine::Baremetal(arch, _) => *arch,
        }
    }

    /// Return a set of cores to run benchmark, run fewer total iterations
    /// and instead more with high core counts.
    pub fn thread_defaults_low_mid_high(&self) -> Vec<usize> {
        if cfg!(feature = "smoke") {
            return vec![1, 4];
        }

        let uniform_threads = self.thread_defaults_uniform();
        let mut threads = Vec::with_capacity(6);

        for low in uniform_threads.iter().take(2) {
            threads.push(*low);
        }

        let mid = uniform_threads.len() / 2;
        if let Some(e) = uniform_threads.get(mid) {
            threads.push(*e);
        }

        for high in uniform_threads.iter().rev().take(3) {
            threads.push(*high);
        }

        threads.sort_unstable();
        threads.dedup();

        threads
    }

    /// Return a set of cores to run benchmark on sampled uniform between
    /// 1..self.max_cores().
    pub fn thread_defaults_uniform(&self) -> Vec<usize> {
        if cfg!(feature = "smoke") {
            return vec![1, 4];
        }

        let max_cores = self.max_cores();
        let nodes = self.max_numa_nodes();

        let mut threads = Vec::with_capacity(12);
        // On larger machines thread increments are bigger than on smaller
        // machines:
        let thread_incremements = if max_cores > 96 {
            16
        } else if max_cores > 24 {
            8
        } else if max_cores > 16 {
            4
        } else {
            2
        };

        for t in (0..(max_cores + 1)).step_by(thread_incremements) {
            if t == 0 {
                // Can't run on 0 threads
                threads.push(t + 1);
            } else {
                threads.push(t);
            }
        }

        threads.push(max_cores / nodes);
        threads.push(max_cores);

        threads.sort_unstable();
        threads.dedup();

        threads
    }

    pub fn max_cores(&self) -> usize {
        if let Machine::Qemu(_) = self {
            let topo = Topology::new().expect("Can't retrieve System topology?");
            topo.objects_with_type(&ObjectType::Core)
                .map_or(1, |cpus| cpus.len())
        } else {
            match self.name() {
                "l0318" => 96,
                "b1542" => 28,
                _ => unreachable!("unknown machine"),
            }
        }
    }

    pub fn max_numa_nodes(&self) -> usize {
        if let Machine::Qemu(_) = self {
            let topo = Topology::new().expect("Can't retrieve System topology?");
            // TODO: Should be ObjectType::NUMANode but this fails in the C library?
            topo.objects_with_type(&ObjectType::Package)
                .map_or(1, |nodes| nodes.len())
        } else {
            match self.name() {
                "l0318" => 4,
                "b1542" => 2,
                _ => unreachable!("unknown machine"),
            }
        }
    }
}

/// A build environement, currently we only have one it has a link to the
/// `target` directory.
///
/// (Ideally we could override this if we ever need to and set the
/// `CARGO_TARGET_DIR`)
///
/// # Note
/// For the tests, all BuildEnvironment's (with different dir) need to be
/// singleton instances, protected for example by a Mutex.
pub struct BuildEnvironment {
    _dir: &'static str,
}

lazy_static! {
    static ref TARGET_DIR: Mutex<BuildEnvironment> =
        Mutex::new(BuildEnvironment { _dir: "target" });
}

/// A type that exists when the given target enviroment has been successfully
/// built with the given BuildArgs.
///
/// Use `BuildArgs::build` to construct (by providing a BuildEnvironment).
pub struct Built<'a> {
    pub with_args: BuildArgs<'a>,
}

/// Arguments passed to the run.py script to build a test.
#[derive(Clone)]
pub struct BuildArgs<'a> {
    /// Test name of kernel integration test.
    kernel_features: Vec<&'a str>,
    /// Features passed to compiled user-space modules.
    user_features: Vec<&'a str>,
    /// Which user-space modules to include.
    mods: Vec<&'a str>,
    /// Should we compile in release mode?
    pub release: bool,
    /// the architecture to build for (x86_64 or aarch64)
    arch: Arch,
}

impl<'a> Default for BuildArgs<'a> {
    fn default() -> BuildArgs<'a> {
        BuildArgs {
            kernel_features: vec!["integration-test"],
            user_features: Vec::new(),
            mods: Vec::new(),
            release: false,
            arch: Arch::X86_64,
        }
    }
}

impl<'a> BuildArgs<'a> {
    pub fn build(self) -> Built<'a> {
        let env = match TARGET_DIR.lock() {
            Ok(env) => env,
            // It's fine to get the environment again if another test failed,
            // and hence poisoned the lock. That's because the lock doesn't
            // contain any state and is just to coordinate access to the build
            // directory (no two builds are using target/ at the same time)
            Err(pe) => pe.into_inner(),
        };

        self.compile(env)
    }

    /// Build the kernel/user-space.
    pub fn compile(self, _env: MutexGuard<'static, BuildEnvironment>) -> Built<'a> {
        let mut compile_args = self.as_cmd();
        compile_args.push("--norun".to_string());
        compile_args.push("net".to_string());
        compile_args.push("--no-network-setup".to_string());

        let o = process::Command::new("python3")
            .args(compile_args.clone())
            // TODO(unimplemented): This will place the new `target` directory
            // under kernel if tests are executed in the kernel directory
            // ideally we just want to customize the name of the directory but
            // still have them in the base-directory -- we'd need this if we
            // ever need to have two different builds per test.
            //
            // .env("CARGO_TARGET_DIR", env.dir)
            .output()
            .expect("failed to build");

        if !o.status.success() {
            io::stdout().write_all(&o.stdout).unwrap();
            io::stderr().write_all(&o.stderr).unwrap();

            panic!("Building test failed: {:?}", compile_args.join(" "));
        }

        Built { with_args: self }
    }

    /// Converts the RunnerArgs to a run.py command line invocation.
    pub fn as_cmd(&'a self) -> Vec<String> {
        // Add features for build
        let kernel_features = String::from(self.kernel_features.join(","));
        let user_features = String::from(self.user_features.join(","));

        let mut cmd = vec![
            "run.py".to_string(),
        ];

        if !self.kernel_features.is_empty() {
            cmd.push("--kfeatures".to_string());
            cmd.push(kernel_features);
        }

        if !self.user_features.is_empty() {
            cmd.push("--ufeatures".to_string());
            cmd.push(user_features);
        }

        if !self.mods.is_empty() {
            cmd.push("--mods".to_string());
            cmd.push(self.mods.join(" "));
        }

        if self.release {
            cmd.push("--release".to_string());
        }

        match self.arch {
            Arch::X86_64 => cmd.push("--target x86_64-qemu".to_string()),
            Arch::Aarch64 => cmd.push("--target aarch64-qemu".to_string()),
        }

        cmd
    }

    /// Add a cargo feature to the kernel build.
    pub fn kernel_feature(mut self, kernel_feature: &'a str) -> BuildArgs<'a> {
        self.kernel_features.push(kernel_feature);
        self
    }

    /// What cargo features should be passed to the user-space modules build.
    pub fn user_features(mut self, user_features: &[&'a str]) -> BuildArgs<'a> {
        self.user_features.extend_from_slice(user_features);
        self
    }

    /// Add a cargo feature to the user-space modules build.
    pub fn user_feature(mut self, user_feature: &'a str) -> BuildArgs<'a> {
        self.user_features.push(user_feature);
        self
    }

    /// Adds a user-space module to the build and deployment.
    pub fn module(mut self, module: &'a str) -> BuildArgs<'a> {
        self.mods.push(module);
        self
    }

    /// Do a release build.
    pub fn release(mut self) -> BuildArgs<'a> {
        self.release = true;
        self
    }

    /// set the architecture of the build
    pub fn arch(&mut self, arch: Arch) -> &mut BuildArgs<'a> {
        self.arch = arch;
        self
    }

}
