module MemoryTypes {
    datatype PAddr = PAddr(base: nat)
    datatype VAddr = VAddr(base: int)
    datatype Frame = Frame(base: PAddr, size: nat)
    datatype TlbFlushHandle = TlbFlushHandle(base: PAddr, size: nat)
}