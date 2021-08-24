module NativeTypes {
  newtype{:nativeType "sbyte"} sbyte = i:int | -0x80 <= i < 0x80
  newtype{:nativeType "byte"} byte = i:int | 0 <= i < 0x100
  newtype{:nativeType "short"} int16 = i:int | -0x8000 <= i < 0x8000
  newtype{:nativeType "ushort"} uint16 = i:int | 0 <= i < 0x10000
  newtype{:nativeType "int"} int32 = i:int | -0x80000000 <= i < 0x80000000
  newtype{:nativeType "uint"} uint32 = i:int | 0 <= i < 0x100000000
  newtype{:nativeType "long"} int64 = i:int | -0x8000000000000000 <= i < 0x8000000000000000
  newtype{:nativeType "ulong"} uint64 = i:int | 0 <= i < 0x1_0000_0000_0000_0000

  newtype{:nativeType "sbyte"} nat8 = i:int | 0 <= i < 0x80
  newtype{:nativeType "short"} nat16 = i:int | 0 <= i < 0x8000
  newtype{:nativeType "int"} nat32 = i:int | 0 <= i < 0x80000000
  newtype{:nativeType "long"} nat64 = i:int | 0 <= i < 0x8000000000000000

  function method Uint64Size() : uint64 { 8 }
  function method Uint32Size() : uint64 { 4 }
  function method Uint16Size() : uint64 { 2 }

  function Uint64UpperBound() : int { 0x1_0000_0000_0000_0000 }
  function Uint32UpperBound() : int { 0x1_0000_0000 }
  function method Uint8UpperBound() : uint64 { 0x100 }

  type uint8 = byte

  newtype/*{:nativeType "__m128i"}*/ uint128 = i:int |
      0 <= i < 0x1_0000_0000_0000_0000_0000_0000_0000_0000
}