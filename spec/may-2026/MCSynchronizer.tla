--------------------------- MODULE MCSynchronizer ---------------------------
(***************************************************************************)
(* Concrete instance of the abstract Synchronizer spec, sized for finite   *)
(* model checking with TLC. Keep these small — TLC explores the full       *)
(* reachable state space.                                                  *)
(*                                                                         *)
(* The constants n1, n2, n3, k1, k2, h1, h2 below are declared as TLC      *)
(* "model values" in MCSynchronizer.cfg (written as `name = name`). Model  *)
(* values are uninterpreted atoms — they're equal to themselves and        *)
(* unequal to everything else. Using them (rather than strings) is what    *)
(* makes the SYMMETRY directive legal: TLC's symmetry reduction requires   *)
(* the symmetric domain to be a set of model values.                       *)
(***************************************************************************)

EXTENDS Synchronizer

\* Synchronizer nodes (the design fixes |Nodes| = 3).
CONSTANTS n1, n2, n3
MCNodes == {n1, n2, n3}

\* Two distinct PCR keys is enough to exercise registration races,
\* transitions, and retirement.
CONSTANTS k1, k2
MCPCRKeys == {k1, k2}

\* Two distinct hash values is enough to make Pin updates observable
\* (different from previous commitment) without blowing up the state
\* space.
CONSTANTS h1, h2
MCHashes == {h1, h2}

\* Bound on log length. With MaxOps=5 the model explores all sequences
\* of up to 5 committed operations, plus their interleavings with
\* proposals, node failures, and recoveries.
MCMaxOps == 5

\* Symmetry reduction. Nodes / keys / hashes are interchangeable —
\* renaming them produces an equivalent execution. Telling TLC about
\* this cuts the state space by a factor of roughly
\* |Nodes|! * |PCRKeys|! * |Hashes|! = 6 * 2 * 2 = 24.
MCSymmetry ==
    Permutations(MCNodes) \cup Permutations(MCPCRKeys) \cup Permutations(MCHashes)

=============================================================================
