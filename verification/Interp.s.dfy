include "./lib/Lang/NativeTypes.s.dfy"
include "./lib/Base/KeyType.s.dfy"
include "MemoryTypes.s.dfy"

module InterpMod {
  import opened KeyType
  import opened MemoryTypes

  datatype Record = Record(va: VAddr, pa: PAddr, len: nat)

  datatype Interp = Interp(mi: map<VAddr, Record>)
  {
    function MapFrame(base: VAddr, frame: Frame) : (outInterp : Interp)
    {
      // TODO: we only have the case that really succeeds here,
      // but maybe we should model the pre-condidtions for this to succeed
      // etc. here as well and return an error? Not sure what is better...
      Interp(mi[base := Record(base, frame.base, frame.size)])
    }

    // I tried to put this stuff here but does it even make sense
    // to have an function here for resolve?
    /*function Resolve(vaddr: VAddr) : (paddr : PAddr)
    {
    }*/

    function Unmap(base: VAddr) : (outInterp : Interp)
    {
      Interp(mi := mi - {base})
    }
  }

  function Empty() : Interp
  {
    Interp(map[])
  }

}
