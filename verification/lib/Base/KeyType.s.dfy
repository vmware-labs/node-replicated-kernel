include "../Lang/NativeTypes.s.dfy"

module KeyType {
  import NativeTypes

  function method MaxLen() : NativeTypes.uint64 { 1024 }
  type Key = s : seq<NativeTypes.byte> | |s| <= 1024
}

module ValueType {
  import NativeTypes

  function method MaxLen() : NativeTypes.uint64 { 1024 }
  type Value(==,!new) = s : seq<NativeTypes.byte> | |s| <= 1024
	function method DefaultValue() : Value { [] }

	function Len(v: Value) : nat { |v| }

  predicate ValidMessageBytestring(s: seq<NativeTypes.byte>)
  {
    |s| <= MaxLen() as int
  }

  predicate ValidMessageBytestrings(strs: seq<seq<NativeTypes.byte>>)
  {
    forall i | 0 <= i < |strs| :: ValidMessageBytestring(strs[i])
  }

  
	export S provides Value, DefaultValue, Len
	export Internal reveals *
	export extends S
}