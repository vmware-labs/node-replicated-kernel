use core::fmt::{Debug, Display};
use custom_error::custom_error;

use alloc::string::String;
use alloc::string::ToString;

custom_error! {pub KError
    ProcessCreate{desc: String}      = "Unable to create process: {desc}",
}

impl From<String> for KError {
    fn from(err: String) -> KError {
        KError::ProcessCreate { desc: err }
    }
}

impl From<&str> for KError {
    fn from(err: &str) -> KError {
        From::from(String::from(err))
    }
}
