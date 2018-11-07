use core::alloc::Layout;
use core::mem::transmute;

use core::fmt;

use x86::bits64::paging;

mod buddy;
mod bump;

pub use self::buddy::FMANAGER;

use arch::memory::{paddr_to_kernel_vaddr, PAddr, VAddr, BASE_PAGE_SIZE};
use slabmalloc::{ObjectPage, PageProvider};

pub trait PhysicalAllocator {
    fn init(&mut self) {}

    unsafe fn add_memory(&mut self, _region: Frame) -> bool {
        false
    }

    unsafe fn allocate(&mut self, _layout: Layout) -> Option<Frame> {
        None
    }

    unsafe fn deallocate(&mut self, _frame: Frame, _layout: Layout) {}

    fn print_info(&self) {}
}

/// Physical region of memory.
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Frame {
    base: PAddr,
    size: usize,
}

impl Frame {
    pub const fn new(base: PAddr, size: usize) -> Frame {
        Frame {
            base: base,
            size: size,
        }
    }

    #[allow(unused)]
    const fn empty() -> Frame {
        Frame {
            base: PAddr::from_u64(0),
            size: 0,
        }
    }

    unsafe fn as_mut_slice<T>(&mut self) -> Option<&mut [T]> {
        if self.size % core::mem::size_of::<T>() == 0 {
            Some(core::slice::from_raw_parts_mut(
                self.kernel_vaddr().as_mut_ptr::<T>(),
                self.size / core::mem::size_of::<T>(),
            ))
        } else {
            None
        }
    }

    #[allow(unused)]
    unsafe fn as_slice<T>(&self) -> Option<&[T]> {
        if self.size % core::mem::size_of::<T>() == 0 {
            Some(core::slice::from_raw_parts(
                self.kernel_vaddr().as_mut_ptr::<T>(),
                self.size / core::mem::size_of::<T>(),
            ))
        } else {
            None
        }
    }

    unsafe fn fill<T: Copy>(&mut self, pattern: T) -> bool {
        self.as_mut_slice::<T>().map_or(false, |obj| {
            for i in 0..obj.len() {
                obj[i] = pattern;
            }
            true
        })
    }

    /// Size of the region (in 4K pages).
    pub fn base_pages(&self) -> usize {
        self.size / BASE_PAGE_SIZE
    }

    /// Size of the region (in bytes).
    pub fn size(&self) -> usize {
        self.size
    }

    pub unsafe fn zero(&mut self) {
        self.fill(0);
    }

    /// The kernel virtual address for this region.
    pub fn kernel_vaddr(&self) -> VAddr {
        paddr_to_kernel_vaddr(self.base)
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Frame {{ 0x{:x} -- 0x{:x} (size = {}, pages = {} }}",
            self.base,
            self.base + self.size,
            self.size,
            self.base_pages()
        )
    }
}

pub trait PageTableProvider<'a> {
    fn allocate_pml4<'b>(&mut self) -> Option<&'b mut paging::PML4>;
    fn new_pdpt(&mut self) -> Option<paging::PML4Entry>;
    fn new_pd(&mut self) -> Option<paging::PDPTEntry>;
    fn new_pt(&mut self) -> Option<paging::PDEntry>;
    fn new_page(&mut self) -> Option<paging::PTEntry>;
}

pub struct BespinPageTableProvider;

impl BespinPageTableProvider {
    pub const fn new() -> BespinPageTableProvider {
        BespinPageTableProvider
    }
}

impl<'a> PageTableProvider<'a> for BespinPageTableProvider {
    /// Allocate a PML4 table.
    fn allocate_pml4<'b>(&mut self) -> Option<&'b mut paging::PML4> {
        unsafe {
            let f = FMANAGER.allocate(Layout::new::<paging::Page>().align_to(BASE_PAGE_SIZE));
            f.map(|frame| {
                let pml4: &'b mut [paging::PML4Entry; 512] =
                    transmute(paddr_to_kernel_vaddr(frame.base));
                pml4
            })
        }
    }

    /// Allocate a new page directory and return a PML4 entry for it.
    fn new_pdpt(&mut self) -> Option<paging::PML4Entry> {
        unsafe {
            FMANAGER
                .allocate(Layout::new::<paging::Page>().align_to(BASE_PAGE_SIZE))
                .map(|frame| {
                    paging::PML4Entry::new(
                        frame.base,
                        paging::PML4Flags::P | paging::PML4Flags::RW | paging::PML4Flags::US,
                    )
                })
        }
    }

    /// Allocate a new page directory and return a pdpt entry for it.
    fn new_pd(&mut self) -> Option<paging::PDPTEntry> {
        unsafe {
            FMANAGER
                .allocate(Layout::new::<paging::Page>().align_to(BASE_PAGE_SIZE))
                .map(|frame| {
                    paging::PDPTEntry::new(
                        frame.base,
                        paging::PDPTFlags::P | paging::PDPTFlags::RW | paging::PDPTFlags::US,
                    )
                })
        }
    }

    /// Allocate a new page-directory and return a page directory entry for it.
    fn new_pt(&mut self) -> Option<paging::PDEntry> {
        unsafe {
            FMANAGER
                .allocate(Layout::new::<paging::Page>().align_to(BASE_PAGE_SIZE))
                .map(|frame| {
                    paging::PDEntry::new(
                        frame.base,
                        paging::PDFlags::P | paging::PDFlags::RW | paging::PDFlags::US,
                    )
                })
        }
    }

    /// Allocate a new (4KiB) page and map it.
    fn new_page(&mut self) -> Option<paging::PTEntry> {
        unsafe {
            FMANAGER
                .allocate(Layout::new::<paging::Page>().align_to(BASE_PAGE_SIZE))
                .map(|frame| {
                    paging::PTEntry::new(
                        frame.base,
                        paging::PTFlags::P | paging::PTFlags::RW | paging::PTFlags::US,
                    )
                })
        }
    }
}

pub struct BespinSlabsProvider;

unsafe impl Send for BespinSlabsProvider {}
unsafe impl Sync for BespinSlabsProvider {}

impl BespinSlabsProvider {
    pub const fn new() -> BespinSlabsProvider {
        BespinSlabsProvider
    }
}

impl<'a> PageProvider<'a> for BespinSlabsProvider {
    fn allocate_page(&mut self) -> Option<&'a mut ObjectPage<'a>> {
        let f =
            unsafe { FMANAGER.allocate(Layout::new::<paging::Page>().align_to(BASE_PAGE_SIZE)) };
        f.map(|frame| unsafe {
            debug!("slabmalloc allocate frame.base = {:x}", frame.base);
            let sp: &'a mut ObjectPage = transmute(paddr_to_kernel_vaddr(frame.base));
            sp
        })
    }

    fn release_page(&mut self, _p: &'a mut ObjectPage<'a>) {
        debug!("TODO!");
    }
}
