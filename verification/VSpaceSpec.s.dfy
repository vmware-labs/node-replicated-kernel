include "./vbtrfs/lib/Lang/NativeTypes.s.dfy"
include "./vbtrfs/lib/Base/KeyType.s.dfy"
include "MemoryTypes.s.dfy"
include "Interp.s.dfy"

module VSpaceSpec {
  import opened KeyType
  import opened MemoryTypes
  import InterpMod

  // UI
  datatype Input = MapFrame(base: VAddr, frame: Frame) | Resolve(base: VAddr, paddr: PAddr) | Unmap(base: VAddr) | NoopInput
  datatype Output = Resolved(pa: PAddr) | Ok | KError | Unmapped(handle: TlbFlushHandle) | NoopOutput

  // State machine
  datatype Variables = Variables(interp: InterpMod.Interp)

  function InitState() : Variables {
    Variables(InterpMod.Empty())
  }

  predicate Resolve(s: Variables, s': Variables, vaddr: VAddr, paddr: PAddr)
  {
    && s' == s

    // This doesn't quite work yet:
    //&& var vaddr_page_aligned := vaddr.base & !0xfff;
    // So constraint to page-size:
    && vaddr.base % 4096 == 0

    && vaddr in s.interp.mi
    && var record := s.interp.mi[vaddr];
    && vaddr.base >= record.va.base
    && vaddr.base < record.va.base + record.len
    // returned PAddr is beginning mapped region + offset within region:
    && paddr == PAddr(record.pa.base + (vaddr.base - record.va.base))
  }

  predicate MapFrame(s: Variables, s': Variables, va: VAddr, frame: Frame)
  {
    // Some simplification of model at the moment:
    && va.base % 4096 == 0
    && frame.base.base % 4096 == 0
    && frame.size == 4096

    // Actual MapFrame
    && s' == s.(interp := s.interp.MapFrame(va, frame))
  }

  predicate Unmap(s: Variables, s': Variables, vaddr: VAddr, handle: TlbFlushHandle)
  {
    // Simplification of model at the moment:
    && vaddr.base % 4096 == 0
    // Actual Unmap
    && s' == s.(interp := s.interp.Unmap(vaddr))

    // TODO: this is awkward aside from updating s.interp
    // I also need to express that:
    // && handle == s.interp.Unmap(vaddr)
    // should I return a tuple? / linear dafny?
  }

  predicate Next(v: Variables, v': Variables, input: Input, out: Output)
  {
  true
    || (
        && input.Resolve?
        // TODO: how to do error handling? should I put it here or inside the spec?
        && ((out.Resolved? && Resolve(v, v', input.base, out.pa)) || out.KError?)
    )
    || (
        && input.MapFrame?
        // TODO: how to do error handling? should I put it here or inside the spec?
        && ((out.Ok? && MapFrame(v, v', input.base, input.frame)) || out.KError?)
       )
    || (
        && input.Unmap?
        // TODO: how to do error handling? should I put it here or inside the spec?
        && ((out.Unmapped? && Unmap(v, v', input.base, out.handle)) || out.KError?)
       )
    || (
        // TODO: why do we need the Noop stuff?
        && input.NoopInput?
        && out.NoopOutput?
        && v' == v
       )
    // TODO: Not quite sure do I need to enumerate all possible states here?
  }
}