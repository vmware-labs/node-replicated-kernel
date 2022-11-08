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
//! * `s06_*`: Rackscale (distributed) tests
//! * `s10_*`: User-space applications benchmarks
//! * `s11_*`: Rackscale (distributed) benchmarks

extern crate testutils;

pub(crate) mod s00_core_tests;
pub(crate) mod s01_kernel_low_tests;
pub(crate) mod s02_kernel_high_tests;
pub(crate) mod s03_kernel_high_tests;
pub(crate) mod s04_user_runtime_tests;
pub(crate) mod s05_user_app_tests;
pub(crate) mod s06_rackscale_tests;

pub(crate) mod s10_benchmarks;
pub(crate) mod s11_rackscale_benchmarks;
