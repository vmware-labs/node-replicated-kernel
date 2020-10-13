//! KCB is the local kernel control that stores all core local state.

use alloc::sync::Arc;
use core::cell::{RefCell, RefMut};
use core::ptr;

use mlnr::Replica as MlnrReplica;
use mlnr::ReplicaToken as MlnrReplicaToken;
use node_replication::Replica;
use node_replication::ReplicaToken;

use crate::kcb::{ArchSpecificKcb, Kcb};
use crate::mlnr::MlnrKernelNode;
use crate::nr::KernelNode;

use super::process::UnixProcess;
use super::vspace::VSpace;
use super::KernelArgs;

static mut KCB: *mut Kcb<ArchKcb> = ptr::null_mut();

pub fn try_get_kcb<'a>() -> Option<&'a mut Kcb<ArchKcb>> {
    unsafe {
        if !KCB.is_null() {
            Some(&mut *KCB as &mut Kcb<ArchKcb>)
        } else {
            None
        }
    }
}

pub fn get_kcb<'a>() -> &'a mut Kcb<ArchKcb> {
    unsafe { &mut *KCB as &mut Kcb<ArchKcb> }
}

unsafe fn set_kcb(kcb: ptr::NonNull<Kcb<ArchKcb>>) {
    KCB = kcb.as_ptr();
}
use core::any::Any;
/// Initialize the KCB in the system.
///
/// Should be called during set-up. Afterwards we can use `get_kcb` safely.
pub(crate) fn init_kcb<A: Any>(mut kcb: &'static mut Kcb<A>) {
    let any_kcb = &mut kcb as &mut dyn Any;
    if let Some(ckcb) = any_kcb.downcast_mut::<&'static mut Kcb<ArchKcb>>() {
        let kptr: ptr::NonNull<Kcb<ArchKcb>> = (*ckcb).into();
        unsafe { set_kcb(kptr) };
    } else {
        panic!("Tried to install incompatible KCB.");
    }
}

#[repr(C)]
pub struct ArchKcb {
    init_vspace: RefCell<VSpace>,
    /// Arguments passed to the kernel by the bootloader.
    kernel_args: &'static KernelArgs,
    pub replica: Option<(Arc<Replica<'static, KernelNode<UnixProcess>>>, ReplicaToken)>,
    pub mlnr_replica: Option<(Arc<MlnrReplica<'static, MlnrKernelNode>>, MlnrReplicaToken)>,
    id: usize,
}

impl ArchKcb {
    pub fn new(kernel_args: &'static KernelArgs) -> ArchKcb {
        ArchKcb {
            kernel_args,
            init_vspace: RefCell::new(VSpace::new()),
            replica: None,
            mlnr_replica: None,
            id: 0,
        }
    }

    pub fn init_vspace(&self) -> RefMut<VSpace> {
        self.init_vspace.borrow_mut()
    }

    pub fn kernel_args(&self) -> &'static KernelArgs {
        self.kernel_args
    }

    pub fn id(&self) -> usize {
        self.id
    }
}

impl ArchSpecificKcb for ArchKcb {
    fn install(&mut self) {}
}
