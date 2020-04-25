#![no_std]
#![feature(used, lang_items, never_type)]

use core::fmt::Error;

#[macro_use(sprintln)]
extern crate klogger;

#[no_mangle]
#[used]
pub static mut __TEST_PANICKED: bool = false;

/// Start the test harness.
pub fn test_start(ntests: usize) {
    sprintln!("running {} tests (using KVM support)", ntests)
}

/// Signals that given test is ignored.
pub fn test_ignored(name: &str) {
    sprintln!("test {} ... ignored", name);
}

pub fn test_before_run(name: &str) {
    sprintln!("test {} ... ", name);
}

pub fn test_panic_fmt(args: core::fmt::Arguments, file: &'static str, line: u32) {
    sprintln!("\npanicked at '");
    sprintln!("', {}:{}", file, line);
}

pub fn test_failed(_name: &str) {
    sprintln!("FAILED");
}

pub fn test_success(_name: &str) {
    sprintln!("OK");
}

pub fn test_summary(passed: usize, failed: usize, ignored: usize) {
    sprintln!(
        "\ntest result: {} {} passed; {} failed; {} ignored",
        if failed == 0 { "OK" } else { "FAILED" },
        passed,
        failed,
        ignored
    );

    if failed != 0 {
        //std::process::exit(101);
    }
}

pub fn test_main_static(tests: &[&TestDescAndFn]) {
    test_start(tests.len());

    let mut failed = 0;
    let mut ignored = 0;
    let mut passed = 0;
    for test in tests {
        if test.desc.ignore {
            ignored += 1;
            test_ignored(test.desc.name.0);
        } else {
            let meta_data = test_before_run(test.desc.name.0);

            unsafe {
                __TEST_PANICKED = false;
            }

            test.testfn.0();

            unsafe {
                if __TEST_PANICKED == (test.desc.should_panic == ShouldPanic::Yes) {
                    passed += 1;
                    test_success(test.desc.name.0);
                } else {
                    failed += 1;
                    test_failed(test.desc.name.0);
                }
            }
        }
    }

    test_summary(passed, failed, ignored);
}

// required for compatibility with the `rustc --test` interface
pub struct TestDescAndFn {
    pub desc: TestDesc,
    pub testfn: StaticTestFn,
}

pub struct TestDesc {
    pub ignore: bool,
    pub name: StaticTestName,
    pub should_panic: ShouldPanic,
    pub allow_fail: bool,
}

pub struct StaticTestName(pub &'static str);
pub struct StaticTestFn(pub fn());

#[derive(PartialEq)]
pub enum ShouldPanic {
    No,
    Yes,
}

/// Invoked when unit tests terminate. Should panic if the unit
/// Tests is considered a failure. By default, invokes `report()`
/// and checks for a `0` result.
pub fn assert_test_result<T: Termination>(result: T) {
    let code = result.report();
    assert_eq!(
        code, 0,
        "the test returned a termination value with a non-zero status code ({}) \
         which indicates a failure",
        code
    );
}

pub trait Termination {
    fn report(self) -> i32;
}

impl Termination for () {
    fn report(self) -> i32 {
        0
    }
}

impl<T: Termination, Error> Termination for Result<T, Error> {
    fn report(self) -> i32 {
        match self {
            Ok(val) => val.report(),
            Err(err) => 101,
        }
    }
}

impl Termination for ! {
    fn report(self) -> i32 {
        unreachable!();
    }
}

impl Termination for bool {
    fn report(self) -> i32 {
        if self {
            0
        } else {
            101
        }
    }
}

impl Termination for i32 {
    fn report(self) -> i32 {
        self
    }
}
