use x86::msr::{rdmsr, wrmsr};
const IA32_APIC_BASE: u32 = 0x1B;
const X2APIC_MSR_BASE: u32 = 0x800;

/*
000H-001H   Reserved    
002H    Local APIC ID Register
003H    Local APIC Version Register    
004H-007H   Reserved
008H    Task Priority Register (TPR)
009H    Reserved
00AH    Processor Priority Register (PPR)
00BH    EOI Register
00CH    Reserved
00DH    Logical Destination Register
00EH    Reserved1
00FH    Spurious Interrupt Vector Register
010H    In-Service Register (ISR); bits 0:31
011H    ISR bits 32:63
012H    ISR bits 64:95
013H    ISR bits 96:127
014H    ISR bits 128:159
015H    ISR bits 160:191
016H    ISR bits 192:223
017H    ISR bits 224:255
018H    Trigger Mode Register (TMR); bits 0:31
019H    TMR bits 32:63
01AH    TMR bits 64:95
01BH    TMR bits 96:127
01CH    TMR bits 128:159
01DH    TMR bits 160:191
01EH    TMR bits 192:223
01FH    TMR bits 224:255
020H    Interrupt Request Register (IRR); bits 0:31
021H    IRR bits32:63
022H    IRR bits 64:95
023H    IRR bits 96:127
024H    IRR bits 128:159
025H    IRR bits 160:191
026H    IRR bits 192:223
027H    IRR bits 224:255
028H    Error Status Register
029H-02EH   Reserved
02FH    Reserved
030H   Interrupt Command Register (ICR); bits 0-63
032H    LVT Timer Register
033H    LVT Thermal Sensor
034H    LVT Performance Monitoring Register
035H    LVT LINT0 Register
036H    LVT LINT1 Register
037H    LVT Error Register
038H    Initial Count Register (for Timer)
039H    Current Count Register (for Timer)
03AH-03DH   Reserved
03EH    Divide Configuration Register (for Timer)
03FH    SELF IPI4
040H-3FFH   Reserved
*/

#[derive(Debug)]
pub struct x2APIC {
    base: u64,
    id: u32,
    version: u32
}

impl x2APIC {
    pub fn new() -> x2APIC {
        let mut apic = x2APIC { base: 0, id: 0, version: 0 };
        unsafe {

            // Enable
            let mut base: u64 = rdmsr(IA32_APIC_BASE);
            base |= 1 << 10; // Enable x2APIC
            base |= 1 << 11; // Enable APIC

            wrmsr(IA32_APIC_BASE, base);
            apic.base = base;

            apic.id = rdmsr(X2APIC_MSR_BASE+0x02) as u32;
            apic.version = rdmsr(X2APIC_MSR_BASE+0x03) as u32;
        }

        apic
    }

    pub fn is_bsp(&self) -> bool {
        (self.base & (1 << 8)) > 0
    }

    pub fn get_id(&self) -> u32 {
        self.id
    }

    pub fn get_version(&self) -> u32 {
        self.version
    }

    pub unsafe fn enable_tsc(&self) {
        // Enable TSC timer
        let mut lvt: u64 = rdmsr(X2APIC_MSR_BASE+0x32);
        lvt |= 0 << 17;
        lvt |= 1 << 18;
        wrmsr(X2APIC_MSR_BASE+0x32, lvt);            
    }

    pub unsafe fn set_tsc(&self, value: u64) {
        wrmsr(0x6e0, value);
    }

    pub unsafe fn send_self_ipi(&self, vector: u64) {
        wrmsr(X2APIC_MSR_BASE+0x83, vector);
    }
}
