#[cfg(target_os = "bespin")]
global_asm!(include_str!("isr.S"));
