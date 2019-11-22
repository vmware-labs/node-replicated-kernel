//! A dummy process implementation for the unix platform.

use crate::process::Process;

pub struct UnixThreadProcess {}

impl Process for UnixThreadProcess {}
