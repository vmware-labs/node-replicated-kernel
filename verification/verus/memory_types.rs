use builtin::*;

// TODO use the tuple wrapper types once they are supported
pub struct MemRegion { pub base: nat, pub size: nat }

#[spec] pub const BASE_PAGE_SIZE: nat = 4096;
