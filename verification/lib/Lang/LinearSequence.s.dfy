// Copyright 2018-2021 VMware, Inc., Microsoft Inc., Carnegie Mellon University, ETH Zurich, and University of Washington
// SPDX-License-Identifier: BSD-2-Clause

include "NativeTypes.s.dfy"
include "LinearMaybe.s.dfy"

module {:extern "LinearExtern"} LinearSequence_s {
  import opened NativeTypes
  import opened LinearMaybe

  function method {:extern "LinearExtern", "seq_get"} seq_get<A>(shared s:seq<A>, i:uint64):(a:A)
      requires i as int < |s|
      ensures a == s[i]

  function method {:extern "LinearExtern", "seq_set"} seq_set<A>(linear s1:seq<A>, i:uint64, a:A):(linear s2:seq<A>) // can be implemented as in-place update
      requires i as nat < |s1|
      ensures s2 == s1[i as nat := a]

  // method {:extern "LinearExtern", "mut_seq_set"} mut_seq_set<A>(linear inout s:seq<A>, i:uint64, a:A)
  //     requires i as nat < |old_s|
  //     ensures s == old_s[i as nat := a]

  function method {:extern "LinearExtern", "seq_length"} seq_length<A>(shared s:seq<A>):(n:uint64)
    requires |s| <= 0xffff_ffff_ffff_ffff
    ensures n as int == |s|

  function method {:extern "LinearExtern", "seq_empty"} seq_empty<A>():(linear s:seq<A>)
    ensures |s| == 0

  function method {:extern "LinearExtern", "seq_alloc"} seq_alloc<A>(length:uint64, a:A):(linear s:seq<A>)
    ensures |s| == length as int
    ensures forall i :: 0 <= i < |s| ==> s[i] == a

  function method {:extern "LinearExtern", "seq_free"} seq_free<A>(linear s:seq<A>):()

  function method {:extern "LinearExtern", "seq_unleash"} seq_unleash<A>(linear s1:seq<A>):(s2:seq<A>)
      ensures s1 == s2

  // must be a method, not a function method, so that we know s is a run-time value, not a ghost value
  method {:extern "LinearExtern", "seq_length_bound"} seq_length_bound<A>(s:seq<A>)
    ensures |s| < 0xffff_ffff_ffff_ffff

  // must be a method, not a function method, so that we know s is a run-time value, not a ghost value
  method {:extern "LinearExtern", "shared_seq_length_bound"} shared_seq_length_bound<A>(shared s:seq<A>)
    ensures |s| < 0xffff_ffff_ffff_ffff

//  // a wrapper object for borrowing immutable sequences. Necessary so that the C++ translation
//  // can use its construction/destruction to track the reference to the borrowed sequence.
//  linear datatype as_linear<A> = AsLinear(a:A)
//
//  function method {:extern "LinearExtern", "share_seq"} share_seq<A>(shared a:as_linear<seq<A>>):(shared s:seq<A>)
//    ensures s == a.a

  // Intended usage:
  //  linear var l := AsLinear(o);  // Give C++ a chance to increment the ref count on o.
  //  M(share_seq(l));              // borrow the seq in the call to M.
  //  linear var AsLinear(_) := l;  // Free the wrapper, giving C++ a chance to drop the ref count.


  type {:extern "predefined"} lseq<A>

  function {:axiom} lseqs_raw<A(00)>(l:lseq<A>):(s:seq<maybe<A>>) // contents of an lseq, as ghost seq
    ensures rank_is_less_than(s, l)


  function lseq_has<A(00)>(l:lseq<A>):(s:seq<bool>)
      ensures |s| == |lseqs_raw(l)|
  {
    seq(|lseqs_raw(l)|, i requires 0 <= i < |lseqs_raw(l)| => has(lseqs_raw(l)[i]))
  }


  lemma {:axiom} axiom_lseqs_rank<A(00)>(l:lseq<A>, s:seq<A>)
    requires |lseqs_raw(l)| == |s|
    requires forall i :: 0 <= i < |s| ==> s[i] == read(lseqs_raw(l)[i])
    ensures rank_is_less_than(s, l)

  lemma {:axiom} axiom_lseqs_extensional<A(00)>(l1:lseq<A>, l2:lseq<A>)
    requires lseqs_raw(l1) == lseqs_raw(l2)
    ensures l1 == l2

  // it's okay to synthesize all the lseqs you want if they're ghosty
  function {:axiom} imagine_lseq_raw<A(00)>(s:seq<maybe<A>>):(l:lseq<A>)
    ensures lseqs_raw(l) == s

  function method {:extern "LinearExtern", "lseq_length_raw"} lseq_length_raw<A(00)>(shared s:lseq<A>):(n:uint64)
    requires |lseqs_raw(s)| <= 0xffff_ffff_ffff_ffff
    ensures n as int == |lseqs_raw(s)|

  function method {:extern "LinearExtern", "lseq_alloc_raw"} lseq_alloc_raw<A(00)>(length:uint64):(linear s:lseq<A>)
      ensures |lseqs_raw(s)| == length as nat
      ensures forall i:nat | i < length as nat :: !has(lseqs_raw(s)[i])

  function method {:extern "LinearExtern", "lseq_free_raw"} lseq_free_raw<A(00)>(linear s:lseq<A>):()
      requires forall i:nat | i < |lseqs_raw(s)| :: !has(lseqs_raw(s)[i])

  // can be implemented as in-place swap
  function method {:extern "LinearExtern", "lseq_swap_raw_fun"} lseq_swap_raw_fun<A(00)>(linear s1:lseq<A>, i:uint64, linear a1:maybe<A>):(linear p:(linear lseq<A>, linear maybe<A>))
      requires i as int < |lseqs_raw(s1)|
      ensures p.1 == lseqs_raw(s1)[i]
      ensures lseqs_raw(p.0) == lseqs_raw(s1)[i as int := a1]

  function method {:extern "LinearExtern", "lseq_share_raw"} lseq_share_raw<A(00)>(shared s:lseq<A>, i:uint64):(shared a:maybe<A>)
      requires i as int < |lseqs_raw(s)|
      ensures a == lseqs_raw(s)[i]

  // must be a method, not a function method, so that we know s is a run-time value, not a ghost value
  method {:extern "LinearExtern", "lseq_length_bound"} lseq_length_bound<A(00)>(shared s:lseq<A>)
    ensures |lseqs_raw(s)| < 0xffff_ffff_ffff_ffff

    // TODO(robj): I think this interface is broken and we should kill it.
  method {:extern "LinearExtern", "TrustedRuntimeSeqResize"} TrustedRuntimeSeqResize<A>(linear s: seq<A>, newlen: uint64)
    returns (linear s2: seq<A>)
    ensures |s2| == newlen as nat
    ensures forall j :: 0 <= j < newlen as nat && j < |s| ==> s2[j] == s[j]

  method {:extern "LinearExtern", "TrustedRuntimeLSeqResize"} TrustedRuntimeLSeqResize<A(00)>(linear s: lseq<A>, newlen: uint64)
    returns (linear s2: lseq<A>)
    ensures |lseqs_raw(s2)| == newlen as nat
    ensures forall j :: 0 <= j < newlen as nat && j < |lseqs_raw(s)| ==> lseq_has(s2)[j] == lseq_has(s)[j]
    ensures forall j :: |lseqs_raw(s)| <= j < newlen as nat ==> lseq_has(s2)[j] == false
    ensures forall j :: 0 <= j < newlen as nat && j < |lseqs_raw(s)| ==> lseqs_raw(s2)[j] == lseqs_raw(s)[j]

} // module
