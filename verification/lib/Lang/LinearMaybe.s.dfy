// Copyright 2018-2021 VMware, Inc., Microsoft Inc., Carnegie Mellon University, ETH Zurich, and University of Washington
// SPDX-License-Identifier: BSD-2-Clause


module {:extern "LinearMaybe"} LinearMaybe {
  // note: cannot test maybe<A> for equality at run-time (because has is ghost)
  type {:extern "predefined"} maybe(!new, 00)<A>

  predicate {:axiom} has<A>(m:maybe<A>)

  // return value in m if has(m), return default ghost A value otherwise
  function {:axiom} read<A(00)>(m:maybe<A>):A

  function method {:extern "LinearMaybe", "peek"} peek<A(00)>(shared m:maybe<A>):(shared a:A)
    requires has(m)
    ensures a == read(m)

  function method {:extern "LinearMaybe", "unwrap"} unwrap<A(00)>(linear m:maybe<A>):(linear a:A)
    requires has(m)
    ensures a == read(m)

  function method {:extern "LinearMaybe", "give"} give<A(00)>(linear a:A):(linear m:maybe<A>)
    ensures has(m)
    ensures read(m) == a
    ensures forall x:maybe<A> {:trigger give(read(x))} | has(x) && a == read(x) :: m == x

  function method {:extern "LinearMaybe", "empty"} empty<A>():(linear m:maybe<A>)
    ensures !has(m)

  function method {:extern "LinearMaybe", "discard"} discard<A>(linear m:maybe<A>):()
    requires !has(m)

  function {:axiom} imagine<A(00)>(h:bool, a:A):(m:maybe<A>)
    ensures has(m) == h
    ensures read(m) == a

  lemma {:axiom} axiom_extensional<A(00)>(m1:maybe<A>, m2:maybe<A>)
    requires has(m1) == has(m2)
    requires read(m1) == read(m2)
    ensures m1 == m2

} // module
