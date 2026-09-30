------------------------------- MODULE MCBig --------------------------------
(***************************************************************************)
(* Larger configuration: MaxOps=8, PCRKeys=2, Hashes=2.                    *)
(*                                                                         *)
(* Compared with MCSynchronizer (MaxOps=5), this explores log sequences    *)
(* up to length 8, exercising deeper interleavings of register/pin/        *)
(* transition chains under quorum and adversarial proposers.               *)
(***************************************************************************)

EXTENDS Synchronizer

CONSTANTS n1, n2, n3
MCNodes == {n1, n2, n3}

CONSTANTS k1, k2
MCPCRKeys == {k1, k2}

CONSTANTS h1, h2
MCHashes == {h1, h2}

MCMaxOps == 8

MCSymmetry ==
    Permutations(MCNodes) \cup Permutations(MCPCRKeys) \cup Permutations(MCHashes)

=============================================================================
