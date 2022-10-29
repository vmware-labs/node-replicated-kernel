// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A set of integration tests to ensure OS functionality is as expected.
//! These tests spawn a QEMU instance and run the OS on it.
//! The output from serial/QEMU is parsed and verified for expected output.
//!
//! The naming scheme of the tests ensures a somewhat useful order of test
//! execution taking into account the dependency chain:
//! * `s00_*`: Core kernel functionality like boot-up and fault handling
//! * `s01_*`: Low level kernel services: SSE, memory allocation etc.
//! * `s02_*`: High level kernel services: ACPI, core booting mechanism, NR, VSpace etc.
//! * `s03_*`: High level kernel functionality: Spawn cores, run user-space programs
//! * `s04_*`: User-space runtimes
//! * `s05_*`: User-space applications
//! * `s06_*`: User-space applications benchmarks

/*
use std::fmt::{self, Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::{io, process};

use hwloc2::{ObjectType, Topology};
use lazy_static::lazy_static;

use csv::WriterBuilder;
use rexpect::errors::*;
use rexpect::process::signal::SIGTERM;
use rexpect::process::wait::WaitStatus;
use rexpect::session::{spawn_command, PtyReplSession};
use rexpect::{spawn, spawn_bash};
use serde::Serialize;
*/

pub(crate) mod common;
pub(crate) mod s00_core_tests;
pub(crate) mod s01_kernel_low_tests;
