use crate::alloc::string::ToString;
use custom_error::custom_error;

use kpi::SystemCallError;

custom_error! {pub VSpaceError
    AlreadyMapped{from: u64, to: u64} = "VSpace operation covers existing mapping ({from} -- {to})",
}

impl Into<SystemCallError> for VSpaceError {
    fn into(self) -> SystemCallError {
        match self {
            VSpaceError::AlreadyMapped { from: _, to: _ } => SystemCallError::VSpaceAlreadyMapped,
            _ => SystemCallError::InternalError,
        }
    }
}
