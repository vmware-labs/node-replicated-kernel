// KCB is the local kernel control that stores all core local state.

use alloc::boxed::Box;
use core::cell::{Ref, RefCell, RefMut};
use core::pin::Pin;
use core::ptr;

use x86::current::segmentation;
use x86::msr::{wrmsr, IA32_KERNEL_GSBASE};

use apic::xapic::XAPIC;

use super::irq;
use super::process::Process;
use super::vspace::VSpace;

use crate::arch::{KernelArgs, Module};
use crate::memory::buddy::BuddyFrameAllocator;
use crate::memory::{PAddr, PhysicalMemoryAllocator};

pub fn try_get_kcb<'a>() -> Option<&'a mut Kcb> {
    unsafe {
        let kcb = segmentation::rdgsbase() as *mut Kcb;
        if kcb != ptr::null_mut() {
            let kptr = ptr::NonNull::new_unchecked(kcb);
            Some(&mut *kptr.as_ptr())
        } else {
            None
        }
    }
}

pub fn get_kcb<'a>() -> &'a mut Kcb {
    unsafe {
        let kcb = segmentation::rdgsbase() as *mut Kcb;
        assert!(kcb != ptr::null_mut());
        let kptr = ptr::NonNull::new_unchecked(kcb);
        &mut *kptr.as_ptr()
    }
}

unsafe fn set_kcb(kcb: ptr::NonNull<Kcb>) {
    // Set up the GS register to point to the KCB
    segmentation::wrgsbase(kcb.as_ptr() as u64);
    // Set up swapgs instruction to reset the gs register to the KCB on irq, trap or syscall
    wrmsr(IA32_KERNEL_GSBASE, kcb.as_ptr() as u64);
}

pub struct Kcb {
    /// Pointer to the syscall stack (this is referenced in assembly early on in exec.S)
    /// and should therefore always be at offset 0 of the Kcb struct!
    syscall_stack_top: *mut u8,
    current_process: Option<RefCell<Process>>,
    kernel_args: RefCell<&'static KernelArgs<[Module; 2]>>,
    kernel_binary: RefCell<&'static [u8]>,
    init_vspace: RefCell<VSpace>,
    pmanager: RefCell<BuddyFrameAllocator>,
    apic: RefCell<XAPIC>,
    interrupt_stack: Option<Pin<Box<[u8; 64 * 0x1000]>>>,
    syscall_stack: Option<Pin<Box<[u8; 64 * 0x1000]>>>,
}

impl Kcb {
    pub fn new(
        kernel_args: &'static KernelArgs<[Module; 2]>,
        kernel_binary: &'static [u8],
        init_vspace: VSpace,
        pmanager: BuddyFrameAllocator,
        apic: XAPIC,
    ) -> Kcb {
        Kcb {
            syscall_stack_top: ptr::null_mut(),
            current_process: None,
            kernel_args: RefCell::new(kernel_args),
            kernel_binary: RefCell::new(kernel_binary),
            init_vspace: RefCell::new(init_vspace),
            pmanager: RefCell::new(pmanager),
            apic: RefCell::new(apic),
            interrupt_stack: None,
            syscall_stack: None,
        }
    }

    pub fn set_syscall_stack(&mut self, mut stack: Pin<Box<[u8; 64 * 0x1000]>>) {
        unsafe {
            self.syscall_stack_top = stack.as_mut_ptr().offset((stack.len()) as isize);
        }
        info!("syscall_stack_top {:p}", self.syscall_stack_top);
        self.syscall_stack = Some(stack);

        // self.syscall_stack_top should be at offset 0 (for assembly)
        debug_assert_eq!(
            (&self.syscall_stack_top as *const _ as usize) - (self as *const _ as usize),
            0
        );

        // the current process entry should be at offset 8 (for assembly)
        debug_assert_eq!(
            (&self.current_process as *const _ as usize) - (self as *const _ as usize),
            8
        );
    }

    pub fn pmanager(&self) -> RefMut<BuddyFrameAllocator> {
        self.pmanager.borrow_mut()
    }

    pub fn apic(&self) -> RefMut<XAPIC> {
        self.apic.borrow_mut()
    }

    pub fn init_vspace(&self) -> RefMut<VSpace> {
        self.init_vspace.borrow_mut()
    }

    pub fn kernel_binary(&self) -> Ref<&'static [u8]> {
        self.kernel_binary.borrow()
    }

    pub fn kernel_args(&self) -> Ref<&'static KernelArgs<[Module; 2]>> {
        self.kernel_args.borrow()
    }
}

pub(crate) fn init_kcb(kcb: &mut Kcb) {
    let kptr: ptr::NonNull<Kcb> = ptr::NonNull::from(kcb);
    unsafe { set_kcb(kptr) };
}
