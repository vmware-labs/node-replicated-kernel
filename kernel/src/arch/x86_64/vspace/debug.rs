// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::transmute;
use core::pin::Pin;

use fallible_collections::{FallibleVec, FallibleVecGlobal};
use log::info;
use x86::controlregs;
use x86::current::paging::*;

use super::page_table::PageTable;
use crate::arch::memory::{paddr_to_kernel_vaddr, PAddr, VAddr};
use crate::error::KError;
use crate::graphviz as dot;

impl PageTable {
    const INITIAL_EDGES_CAPACITY: usize = 128;
    const INITIAL_NODES_CAPACITY: usize = 128;

    fn parse_nodes_edges<'a>(
        &'a self,
    ) -> Result<(dot::Nodes<'a, Nd<'a>>, dot::Edges<'a, Ed<'a>>), KError> {
        let mut nodes = Vec::try_with_capacity(PageTable::INITIAL_NODES_CAPACITY)?;
        let mut edges = Vec::try_with_capacity(PageTable::INITIAL_EDGES_CAPACITY)?;

        let pml4_table = self.pml4.as_ref();
        nodes.try_push(Nd::PML4(pml4_table, None))?;

        unsafe {
            for (pml_idx, pml_item) in pml4_table.iter().enumerate() {
                let from = Nd::PML4(pml4_table, None);

                if pml_item.is_present() {
                    let pdpt_table =
                        transmute::<VAddr, &mut PDPT>(VAddr::from_u64(pml_item.address().as_u64()));
                    let to = Nd::PDPT(pdpt_table, None);
                    nodes.try_push(to.clone())?;
                    edges.try_push(((from.clone(), pml_idx), (to.clone(), 0)))?;

                    let from = to;
                    for (pdpt_idx, pdpt_item) in pdpt_table.iter().enumerate() {
                        if pdpt_item.is_present() {
                            let pd_table = transmute::<VAddr, &mut PD>(VAddr::from_u64(
                                pdpt_item.address().as_u64(),
                            ));
                            if pdpt_item.is_page() {
                                let _vaddr: usize = (512 * (512 * (512 * 0x1000))) * pml_idx
                                    + (512 * (512 * 0x1000)) * pdpt_idx;
                                let _to = Nd::HugePage(pdpt_item.address());
                                //nodes.try_push(to.clone())?;
                                //edges.try_push((from.clone(), to.clone()))?;
                            } else {
                                let to = Nd::PD(pd_table, None);
                                nodes.try_push(to.clone())?;
                                edges.try_push(((from.clone(), pdpt_idx), (to.clone(), 0)))?;

                                let from = to;
                                for (pd_idx, pd_item) in pd_table.iter().enumerate() {
                                    if pd_item.is_present() {
                                        let ptes = transmute::<VAddr, &mut PT>(VAddr::from_u64(
                                            pd_item.address().as_u64(),
                                        ));

                                        if pd_item.is_page() {
                                            let _vaddr: usize = (512 * (512 * (512 * 0x1000)))
                                                * pml_idx
                                                + (512 * (512 * 0x1000)) * pdpt_idx
                                                + (512 * 0x1000) * pd_idx;
                                            //let to = Nd::LargePage(pd_item.address());
                                            //nodes.try_push(to.clone())?;
                                            //edges.try_push((from.clone(), to.clone()))?;
                                        } else {
                                            let to = Nd::PT(ptes, None);
                                            nodes.try_push(to.clone())?;
                                            edges.try_push((
                                                (from.clone(), pd_idx),
                                                (to.clone(), 0),
                                            ))?;

                                            /*let from = to.clone();
                                            assert!(!pd_item.is_page());
                                            for (pte_idx, pte) in ptes.iter().enumerate() {
                                                let vaddr: usize = (512 * (512 * (512 * 0x1000)))
                                                    * pml_idx
                                                    + (512 * (512 * 0x1000)) * pdpt_idx
                                                    + (512 * 0x1000) * pd_idx
                                                    + (0x1000) * pte_idx;

                                                if pte.is_present() {
                                                    let to = Nd::Page(pte.address());
                                                    nodes.try_push(to.clone())?;
                                                    edges.try_push((from.clone(), to.clone()))?;
                                                }
                                            }*/
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok((nodes.into(), edges.into()))
    }
}

#[allow(unused)]
pub unsafe fn dump_current_table(log_level: usize) {
    let cr_three: u64 = controlregs::cr3();
    let pml4: PAddr = PAddr::from(cr_three);
    let pml4_table = transmute::<VAddr, &PML4>(paddr_to_kernel_vaddr(pml4));

    dump_table(pml4_table, log_level);
}

#[allow(unused)]
pub unsafe fn dump_table(pml4_table: &PML4, log_level: usize) {
    for (pml_idx, pml_item) in pml4_table.iter().enumerate() {
        if pml_item.is_present() {
            info!("PML4 item#{}: maps to {:?}", pml_idx, pml_item);

            let pdpt_table =
                transmute::<VAddr, &mut PDPT>(VAddr::from_u64(pml_item.address().as_u64()));
            if log_level <= 1 {
                continue;
            }

            for (pdpt_idx, pdpt_item) in pdpt_table.iter().enumerate() {
                info!("PDPT item#{}: maps to {:?}", pdpt_idx, pdpt_item);

                if pdpt_item.is_present() {
                    let pd_table =
                        transmute::<VAddr, &mut PD>(VAddr::from_u64(pdpt_item.address().as_u64()));
                    if pdpt_item.is_page() {
                        let vaddr: usize = (512 * (512 * (512 * 0x1000))) * pml_idx
                            + (512 * (512 * 0x1000)) * pdpt_idx;

                        info!("PDPT item: vaddr 0x{:x} maps to {:?}", vaddr, pdpt_item);
                    } else {
                        for (pd_idx, pd_item) in pd_table.iter().enumerate() {
                            info!("PD item#{}: maps to {:?}", pd_idx, pd_item);

                            if pd_item.is_present() {
                                let ptes = transmute::<VAddr, &mut PT>(VAddr::from_u64(
                                    pd_item.address().as_u64(),
                                ));

                                if pd_item.is_page() {
                                    let vaddr: usize = (512 * (512 * (512 * 0x1000))) * pml_idx
                                        + (512 * (512 * 0x1000)) * pdpt_idx
                                        + (512 * 0x1000) * pd_idx;

                                    info!("PD item: vaddr 0x{:x} maps to {:?}", vaddr, pd_item);
                                } else {
                                    assert!(!pd_item.is_page());
                                    for (pte_idx, pte) in ptes.iter().enumerate() {
                                        let vaddr: usize = (512 * (512 * (512 * 0x1000))) * pml_idx
                                            + (512 * (512 * 0x1000)) * pdpt_idx
                                            + (512 * 0x1000) * pd_idx
                                            + (0x1000) * pte_idx;

                                        if pte.is_present() {
                                            info!(
                                                "PT item: vaddr 0x{:x} maps to flags {:?}",
                                                vaddr, pte
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Clone)]
pub(crate) enum Nd<'a> {
    HugePage(PAddr),
    PT(&'a PT, Option<usize>),
    PD(&'a PD, Option<usize>),
    PDPT(&'a PDPT, Option<usize>),
    PML4(Pin<&'a PML4>, Option<usize>),
}

/// Edge is connection of two nodes and slot within the page-table.
type Ed<'a> = ((Nd<'a>, usize), (Nd<'a>, usize));

impl<'a> dot::Labeller<'a> for PageTable {
    type Node = Nd<'a>;
    type Edge = Ed<'a>;

    fn graph_id(&'a self) -> dot::Id<'a> {
        dot::Id::new("vspace").unwrap()
    }

    fn node_shape(&'a self, n: &Self::Node) -> Option<dot::LabelText<'a>> {
        match n {
            Nd::PT(_pt, _) => Some(dot::LabelText::label("record")),
            Nd::PD(_pd, _) => Some(dot::LabelText::label("record")),
            Nd::PDPT(_pdpt, _) => Some(dot::LabelText::label("record")),
            Nd::PML4(_pml4, _) => Some(dot::LabelText::label("record")),
            Nd::HugePage(_addr) => None,
        }
    }

    /// Generate a label that looks like this:
    /// `<f0> PML4_0x400035c00008 | <f1> PML4_0x400035c000016 | (nil) | ... | (nil) `
    fn node_label(&'a self, n: &Self::Node) -> dot::LabelText<'a> {
        let mut node_label = String::with_capacity(512 * 8);

        enum Printer {
            EmitLine,
            EmitDots,
            Skip,
        }

        let label = match n {
            Nd::PT(pt, _) => {
                let mut state = Printer::EmitLine;
                for pt_idx in 0..pt.len() {
                    if pt_idx == 511 {
                        state = Printer::EmitLine;
                    }
                    let pt_item = pt[pt_idx];

                    match state {
                        Printer::EmitLine => {
                            if pt_item.is_present() {
                                if node_label.len() > 0 {
                                    node_label += " | "
                                }
                                node_label +=
                                    format!("<f{}> {:#x}", pt_idx, pt_item.address(),).as_str();

                                if pt_idx < 511 && pt[pt_idx + 1].is_present() {
                                    state = Printer::EmitDots;
                                } else {
                                    state = Printer::EmitLine;
                                }
                            }
                        }
                        Printer::EmitDots => {
                            if node_label.len() > 0 {
                                node_label += " | "
                            }
                            node_label += "...";

                            if pt_idx < 511 && pt[pt_idx + 1].is_present() {
                                state = Printer::Skip;
                            } else {
                                state = Printer::EmitLine;
                            }
                        }
                        Printer::Skip => {
                            if pt_idx < 511 && pt[pt_idx + 1].is_present() {
                                state = Printer::Skip;
                            } else {
                                state = Printer::EmitLine;
                            }
                        }
                    }
                }
                node_label
            }
            Nd::PD(pd, _) => {
                let mut state = Printer::EmitLine;
                for pd_idx in 0..pd.len() {
                    if pd_idx == 511 {
                        state = Printer::EmitLine;
                    }

                    let pd_item = pd[pd_idx];

                    match state {
                        Printer::EmitLine => {
                            if pd_item.is_present() {
                                if node_label.len() > 0 {
                                    node_label += " | "
                                }
                                node_label +=
                                    format!("<f{}> {:#x}", pd_idx, pd_item.address(),).as_str();

                                if pd_idx < 511 && pd[pd_idx + 1].is_present() {
                                    state = Printer::EmitDots;
                                } else {
                                    state = Printer::EmitLine;
                                }
                            }
                        }
                        Printer::EmitDots => {
                            if node_label.len() > 0 {
                                node_label += " | "
                            }
                            node_label += "...";

                            if pd_idx < 511 && pd[pd_idx + 1].is_present() {
                                state = Printer::Skip;
                            } else {
                                state = Printer::EmitLine;
                            }
                        }
                        Printer::Skip => {
                            if pd_idx < 511 && pd[pd_idx + 1].is_present() {
                                state = Printer::Skip;
                            } else {
                                state = Printer::EmitLine;
                            }
                        }
                    }
                }
                node_label
            }
            Nd::PDPT(pdpt, _) => {
                for (pdpt_idx, pdpt_item) in pdpt.iter().enumerate() {
                    if pdpt_item.is_present() {
                        if node_label.len() > 0 {
                            node_label += " | "
                        }
                        node_label +=
                            format!("<f{}> {:#x}", pdpt_idx, pdpt_item.address(),).as_str();
                    }
                }
                node_label
            }
            Nd::PML4(pml4, _) => {
                for (pml_idx, pml_item) in pml4.iter().enumerate() {
                    if pml_item.is_present() {
                        if node_label.len() > 0 {
                            node_label += " | "
                        }
                        node_label += format!("<f{}> {:#x}", pml_idx, pml_item.address(),).as_str();
                    }
                }
                node_label
            }
            Nd::HugePage(addr) => format!("Page1GiB_{:#x}", addr),
        };

        dot::LabelText::label(label)
    }

    fn node_id(&'a self, n: &Nd) -> dot::Id<'a> {
        let label = match n {
            Nd::PT(pt, None) => format!("PT_{:p}", *pt),
            Nd::PD(pd, None) => format!("PD_{:p}", *pd),
            Nd::PDPT(pdpt, None) => format!("PDPT_{:p}", *pdpt),
            Nd::PML4(pml4, None) => format!("PDPT_{:p}", *pml4),
            Nd::PT(pt, Some(slot)) => format!("PT_{:p}:f{}", *pt, slot),
            Nd::PD(pd, Some(slot)) => format!("PD_{:p}:f{}", *pd, slot),
            Nd::PDPT(pdpt, Some(slot)) => format!("PDPT_{:p}:f{}", *pdpt, slot),
            Nd::PML4(pml4, Some(slot)) => format!("PML4_{:p}:f{}", *pml4, slot),
            Nd::HugePage(addr) => format!("Page1GiB_{:#x}", addr),
        };

        dot::Id::new(label).expect("Can't make label")
    }
}

impl<'a> dot::GraphWalk<'a> for PageTable {
    type Node = Nd<'a>;
    type Edge = Ed<'a>;
    fn nodes(&self) -> dot::Nodes<'a, Nd> {
        // Failure ok this is only used for debugging
        let (nodes, _) = self.parse_nodes_edges().expect("Can't parse nodes");
        nodes.into()
    }

    fn edges(&'a self) -> dot::Edges<'a, Ed> {
        // Failure ok this is only used for debugging
        let (_, edges) = self.parse_nodes_edges().expect("Can't parse edges");
        edges.into()
    }

    fn source(&self, e: &Ed<'a>) -> Nd<'a> {
        match (e.0).0 {
            Nd::HugePage(_) => (e.0).0,
            Nd::PT(ptr, None) => Nd::PT(ptr, Some((e.0).1)),
            Nd::PD(ptr, None) => Nd::PD(ptr, Some((e.0).1)),
            Nd::PDPT(ptr, None) => Nd::PDPT(ptr, Some((e.0).1)),
            Nd::PML4(ptr, None) => Nd::PML4(ptr, Some((e.0).1)),
            _ => unimplemented!(),
        }
    }

    fn target(&self, e: &Ed<'a>) -> Nd<'a> {
        match (e.1).0 {
            Nd::HugePage(_) => (e.1).0,
            Nd::PT(ptr, None) => Nd::PT(ptr, Some((e.1).1)),
            Nd::PD(ptr, None) => Nd::PD(ptr, Some((e.1).1)),
            Nd::PDPT(ptr, None) => Nd::PDPT(ptr, Some((e.1).1)),
            Nd::PML4(ptr, None) => Nd::PML4(ptr, Some((e.1).1)),
            _ => unimplemented!(),
        }
    }
}
