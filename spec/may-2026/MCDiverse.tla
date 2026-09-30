----------------------------- MODULE MCDiverse ------------------------------
(***************************************************************************)
(* Diversity configuration: PCRKeys=3, Hashes=2, MaxOps=7.                 *)
(*                                                                         *)
(* Compared with MCBig (PCRKeys=2), this exposes scenarios involving       *)
(* three independent identities — multi-step transition chains             *)
(* (k1 -> k2 -> k3), concurrent registrations of distinct keys, retired    *)
(* keys interacting with newly-attested ones.                              *)
(***************************************************************************)

EXTENDS Synchronizer

CONSTANTS n1, n2, n3
MCNodes == {n1, n2, n3}

CONSTANTS k1, k2, k3
MCPCRKeys == {k1, k2, k3}

CONSTANTS h1, h2
MCHashes == {h1, h2}

MCMaxOps == 5

MCSymmetry ==
    Permutations(MCNodes) \cup Permutations(MCPCRKeys) \cup Permutations(MCHashes)

=============================================================================
