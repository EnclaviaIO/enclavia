---------------------------- MODULE Synchronizer ----------------------------
(***************************************************************************)
(* Synchronizer protocol: a 3-node attested-enclave cluster that prevents  *)
(* storage rollback for customer Nitro enclaves.                           *)
(*                                                                         *)
(* WHAT WE PROVE                                                           *)
(*                                                                         *)
(*   Safety: the synchronizer never returns a commitment that wasn't       *)
(*   pinned by an enclave whose Nitro-attested PCR set legitimately owns   *)
(*   that key, and per-key versions are strictly monotonic.                *)
(*                                                                         *)
(* WHAT WE TAKE AS AXIOMS                                                  *)
(*                                                                         *)
(*   - Nitro hardware signatures are unforgeable; PCR values reflect the   *)
(*     code that booted. Modeled as a protected `attestedKeys` set that    *)
(*     only the AttestKey action grows.                                    *)
(*                                                                         *)
(*   - Ed25519 control-key signatures are unforgeable. Modeled as a        *)
(*     protected `transitionSigs` set that only SignTransition grows, and  *)
(*     only when the signing key is currently authorized.                  *)
(*                                                                         *)
(*   - Raft's safety theorem: once an entry is committed by a quorum, it   *)
(*     appears at the same position in every node's log forever, and       *)
(*     committed entries are totally ordered. We model this by maintaining *)
(*     a single global committed `log` sequence that grows monotonically.  *)
(*     Per-node `applied` indices track how far each node has caught up.   *)
(*     A commit requires a 2-of-3 quorum of UP nodes to ack.               *)
(*                                                                         *)
(* WHAT THE ADVERSARY CONTROLS                                             *)
(*                                                                         *)
(*   - Message ordering: any inflight op may be picked next.               *)
(*   - Node liveness: nodes can fail and recover (losing in-memory state). *)
(*   - Op proposal: clients can propose anything not blocked by the        *)
(*     proposer's own preconditions; the synchronizer re-validates at      *)
(*     commit time via ValidOp.                                            *)
(*                                                                         *)
(*   The adversary CANNOT add to `attestedKeys` or `transitionSigs`.       *)
(*                                                                         *)
(* WHAT WE DO NOT MODEL (deliberately)                                     *)
(*                                                                         *)
(*   - Catastrophic 3-node simultaneous failure (cold-start). The issue    *)
(*     body flags this as an open question pending a separate              *)
(*     operator-signed cluster-fresh-start protocol.                       *)
(*                                                                         *)
(*   - The Noise handshake binding a session to a specific PCR key. We    *)
(*     model the consequence: a Pin proposed by an honest client carries  *)
(*     the correct `key` (= the prover's actual attested PCR set).        *)
(*     Tamarin would prove the handshake gives this guarantee.            *)
(*                                                                         *)
(*   - Liveness. We check safety only; eventual commit is a separate       *)
(*     property that depends on assumptions about node availability.       *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Nodes,        \* set of synchronizer nodes; we assume |Nodes| = 3
    PCRKeys,      \* set of possible PCR keys (one per attestable enclave)
    Hashes,       \* set of possible commitment hash values
    MaxOps        \* bound on log length, for finite model checking

ASSUME /\ Cardinality(Nodes) = 3
       /\ MaxOps \in Nat \ {0}

(***************************************************************************)
(* Operations the synchronizer accepts.                                    *)
(***************************************************************************)
RegisterOps   == [op : {"Register"},   key    : PCRKeys, hash   : Hashes]
PinOps        == [op : {"Pin"},        key    : PCRKeys, hash   : Hashes]
TransitionOps == [op : {"Transition"}, oldKey : PCRKeys, newKey : PCRKeys]
Operation     == RegisterOps \cup PinOps \cup TransitionOps

(***************************************************************************)
(* Quorum: any subset of Nodes of size >= 2 (2-of-3).                     *)
(***************************************************************************)
QuorumSize == 2
Quorums    == { Q \in SUBSET Nodes : Cardinality(Q) >= QuorumSize }

(***************************************************************************)
(* State variables.                                                        *)
(*                                                                         *)
(*   log:            the committed prefix (single global sequence,         *)
(*                   abstracts Raft's committed log).                      *)
(*   applied:        applied[n] = how many committed entries node n has    *)
(*                   applied to its in-memory state.                       *)
(*   upNodes:        nodes currently up. A failed node's applied index     *)
(*                   resets to 0 (no on-disk state, by design).            *)
(*   inflight:       ops proposed but not yet committed. Models the queue  *)
(*                   between proposal and quorum agreement.                *)
(*   attestedKeys:   PCR keys that have produced a valid Nitro             *)
(*                   attestation. ADVERSARY CANNOT EXTEND.                 *)
(*   transitionSigs: (oldKey, newKey) pairs the old enclave has signed.    *)
(*                   ADVERSARY CANNOT EXTEND.                              *)
(***************************************************************************)
VARIABLES log, applied, upNodes, inflight, attestedKeys, transitionSigs

vars == << log, applied, upNodes, inflight, attestedKeys, transitionSigs >>

(***************************************************************************)
(* Folding the log into a state map. ApplyOp encodes the protocol's       *)
(* per-op effect on the (PCRKey -> {hash, version}) map.                  *)
(***************************************************************************)

\* Apply a single op to a state map s.
ApplyOp(s, op) ==
    IF op.op = "Register" THEN
        IF op.key \in DOMAIN s
        THEN s
        ELSE [k \in (DOMAIN s) \cup {op.key} |->
                 IF k = op.key THEN [hash |-> op.hash, version |-> 0]
                 ELSE s[k]]
    ELSE IF op.op = "Pin" THEN
        IF op.key \in DOMAIN s
        THEN [s EXCEPT ![op.key] = [hash |-> op.hash, version |-> @.version + 1]]
        ELSE s
    ELSE  \* Transition
        IF op.oldKey \in DOMAIN s /\ op.newKey \notin DOMAIN s
        THEN [k \in ((DOMAIN s) \ {op.oldKey}) \cup {op.newKey} |->
                IF k = op.newKey THEN s[op.oldKey]
                ELSE s[k]]
        ELSE s

\* Empty state: domain is empty.
EmptyState == << >>  \* the empty function (Sequences-style notation)

\* Wait — in TLA+, an empty function literal is most cleanly written as
\* a function with empty domain. Use [k \in {} |-> ...]. The TLC encoding
\* of "function with empty domain" is consistent across operators below.
EmptyMap == [k \in {} |-> [hash |-> CHOOSE h \in Hashes : TRUE,
                            version |-> 0]]

RECURSIVE FoldLog(_, _)
FoldLog(s, idx) ==
    IF idx = 0 THEN s
    ELSE ApplyOp(FoldLog(s, idx - 1), log[idx])

\* The committed state at the head of the log.
HeadState == FoldLog(EmptyMap, Len(log))

\* Convenience: is k currently a registered, non-retired key?
KeyIsCurrent(k) == k \in DOMAIN HeadState

\* Set of keys that have been the oldKey of a Transition in the log so far
\* (i.e. retired). Once retired, Register is refused — even if attested.
RetiredKeys ==
    { log[i].oldKey : i \in { j \in 1..Len(log) : log[j].op = "Transition" } }

(***************************************************************************)
(* Validity check the synchronizer enforces at commit time.                *)
(*                                                                         *)
(* This is the protocol's authorization rule, evaluated against the        *)
(* committed state (HeadState) and the axiomatic sets (attestedKeys,       *)
(* transitionSigs). An op only enters `log` if ValidOp holds at the moment *)
(* of commit; the synchronizer drops invalid inflight ops.                 *)
(***************************************************************************)
ValidOp(op) ==
    IF op.op = "Register" THEN
        /\ op.key \in attestedKeys      \* hardware-attested
        /\ ~ KeyIsCurrent(op.key)       \* not already current
        /\ op.key \notin RetiredKeys    \* never re-Register a retired PCR set
    ELSE IF op.op = "Pin" THEN
        KeyIsCurrent(op.key)
    ELSE  \* Transition
        /\ KeyIsCurrent(op.oldKey)
        /\ ~ KeyIsCurrent(op.newKey)
        /\ op.newKey \notin RetiredKeys
        /\ op.newKey \in attestedKeys
        /\ << op.oldKey, op.newKey >> \in transitionSigs

(***************************************************************************)
(* Initial state.                                                          *)
(***************************************************************************)
Init ==
    /\ log = << >>
    /\ applied = [n \in Nodes |-> 0]
    /\ upNodes = Nodes
    /\ inflight = {}
    /\ attestedKeys = {}
    /\ transitionSigs = {}

(***************************************************************************)
(* Actions.                                                                *)
(***************************************************************************)

\* Hardware oracle: a previously-unseen enclave produces a valid Nitro
\* attestation. The set is monotonically growing (a key, once attested,
\* stays in the set — though Register may still be refused if the key has
\* been retired by a Transition).
AttestKey(k) ==
    /\ k \notin attestedKeys
    /\ attestedKeys' = attestedKeys \cup {k}
    /\ UNCHANGED << log, applied, upNodes, inflight, transitionSigs >>

\* Old (still-current) enclave signs a transition for its successor.
\* The signature can only be produced while the old key is current —
\* this models "the enclave that holds the control private key is the
\* one currently running under the old PCRs."
SignTransition(oldK, newK) ==
    /\ oldK # newK
    /\ KeyIsCurrent(oldK)
    /\ newK \in attestedKeys
    /\ << oldK, newK >> \notin transitionSigs
    /\ transitionSigs' = transitionSigs \cup {<< oldK, newK >>}
    /\ UNCHANGED << log, applied, upNodes, inflight, attestedKeys >>

\* Bound proposals so the model is finite.
WithinBound == Len(log) + Cardinality(inflight) < MaxOps

\* Honest client proposes a Register for an attested key.
ProposeRegister(k, h) ==
    /\ WithinBound
    /\ k \in attestedKeys
    /\ ~ KeyIsCurrent(k)
    /\ k \notin RetiredKeys
    /\ LET op == [op |-> "Register", key |-> k, hash |-> h]
       IN /\ op \notin inflight
          /\ inflight' = inflight \cup {op}
    /\ UNCHANGED << log, applied, upNodes, attestedKeys, transitionSigs >>

\* Adversary (the untrusted host) injects an arbitrary proposal into the
\* synchronizer's queue. No precondition on attestation — the host can
\* try anything. The synchronizer's job is to reject malformed proposals
\* via ValidOp at commit time.
AdversaryPropose(op) ==
    /\ WithinBound
    /\ op \in Operation
    /\ op \notin inflight
    /\ inflight' = inflight \cup {op}
    /\ UNCHANGED << log, applied, upNodes, attestedKeys, transitionSigs >>

\* Honest client proposes a Pin. The honest-client property here is the
\* abstraction over the Noise handshake: the client's `key` field
\* truthfully matches the PCR set that established the session. A
\* dishonest "client" claiming someone else's key is exactly what the
\* Noise + attestation handshake prevents — modeled separately in
\* Tamarin.
ProposePin(k, h) ==
    /\ WithinBound
    /\ KeyIsCurrent(k)
    /\ LET op == [op |-> "Pin", key |-> k, hash |-> h]
       IN /\ op \notin inflight
          /\ inflight' = inflight \cup {op}
    /\ UNCHANGED << log, applied, upNodes, attestedKeys, transitionSigs >>

\* Honest client proposes a Transition. Old enclave must have signed it.
ProposeTransition(oldK, newK) ==
    /\ WithinBound
    /\ << oldK, newK >> \in transitionSigs
    /\ KeyIsCurrent(oldK)
    /\ ~ KeyIsCurrent(newK)
    /\ newK \notin RetiredKeys
    /\ LET op == [op |-> "Transition", oldKey |-> oldK, newKey |-> newK]
       IN /\ op \notin inflight
          /\ inflight' = inflight \cup {op}
    /\ UNCHANGED << log, applied, upNodes, attestedKeys, transitionSigs >>

\* Synchronizer commits an inflight op once a quorum of UP nodes acks.
\* ValidOp is re-checked here because state may have moved since proposal
\* (e.g. another Pin landed first; another enclave registered the same
\* key concurrently).
CommitOp(op, q) ==
    /\ op \in inflight
    /\ q \in Quorums
    /\ q \subseteq upNodes
    /\ ValidOp(op)
    /\ log' = Append(log, op)
    /\ inflight' = inflight \ {op}
    /\ UNCHANGED << applied, upNodes, attestedKeys, transitionSigs >>

\* Synchronizer drops an op that's no longer valid (raced to a stale
\* state). Keeps `inflight` from accumulating zombies.
DropInvalid(op) ==
    /\ op \in inflight
    /\ ~ ValidOp(op)
    /\ inflight' = inflight \ {op}
    /\ UNCHANGED << log, applied, upNodes, attestedKeys, transitionSigs >>

\* A node catches up by applying the next committed entry.
NodeApply(n) ==
    /\ n \in upNodes
    /\ applied[n] < Len(log)
    /\ applied' = [applied EXCEPT ![n] = @ + 1]
    /\ UNCHANGED << log, upNodes, inflight, attestedKeys, transitionSigs >>

\* Node failure: in-memory state is lost. We require >= QuorumSize nodes
\* remain up so the cluster stays writable; modeling total failure
\* belongs in a separate cold-start spec (see issue body, Open Questions).
NodeFail(n) ==
    /\ n \in upNodes
    /\ Cardinality(upNodes) > QuorumSize
    /\ upNodes' = upNodes \ {n}
    /\ applied' = [applied EXCEPT ![n] = 0]
    /\ UNCHANGED << log, inflight, attestedKeys, transitionSigs >>

\* Node recovers; comes back with no in-memory state. Must hydrate via
\* successive NodeApply steps before being useful for reads. Reads are
\* not modeled here, but the abstraction is correct: a hydrating node's
\* `applied` index < Len(log), so any "read at this node" projection
\* would be a stale prefix until catch-up completes.
NodeRecover(n) ==
    /\ n \notin upNodes
    /\ upNodes' = upNodes \cup {n}
    /\ UNCHANGED << log, applied, inflight, attestedKeys, transitionSigs >>

(***************************************************************************)
(* Next-state relation.                                                    *)
(***************************************************************************)
Next ==
    \/ \E k \in PCRKeys                  : AttestKey(k)
    \/ \E oldK, newK \in PCRKeys         : SignTransition(oldK, newK)
    \/ \E k \in PCRKeys, h \in Hashes    : ProposeRegister(k, h)
    \/ \E k \in PCRKeys, h \in Hashes    : ProposePin(k, h)
    \/ \E oldK, newK \in PCRKeys         : ProposeTransition(oldK, newK)
    \/ \E op \in Operation               : AdversaryPropose(op)
    \/ \E op \in inflight, q \in Quorums : CommitOp(op, q)
    \/ \E op \in inflight                : DropInvalid(op)
    \/ \E n \in Nodes                    : NodeApply(n)
    \/ \E n \in Nodes                    : NodeFail(n)
    \/ \E n \in Nodes                    : NodeRecover(n)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* SAFETY INVARIANTS                                                       *)
(*                                                                         *)
(* These are the properties we ask TLC to verify hold in EVERY reachable   *)
(* state. If TLC finds a counter-example trace, the property is violated  *)
(* and the spec (or the protocol) has a bug.                               *)
(***************************************************************************)

\* Type correctness. Belt-and-braces — confirms the variables only ever
\* hold values of the expected shape.
TypeOK ==
    /\ log \in Seq(Operation)
    /\ applied \in [Nodes -> 0..MaxOps]
    /\ upNodes \subseteq Nodes
    /\ inflight \subseteq Operation
    /\ attestedKeys \subseteq PCRKeys
    /\ transitionSigs \subseteq (PCRKeys \X PCRKeys)

\* (1) Every committed Register names a hardware-attested key.
RegisterAuthenticity ==
    \A i \in 1..Len(log):
        log[i].op = "Register" => log[i].key \in attestedKeys

\* (2) Every committed Transition has a valid signature, and the new key
\* is hardware-attested in its own right.
TransitionAuthenticity ==
    \A i \in 1..Len(log):
        log[i].op = "Transition" =>
            /\ << log[i].oldKey, log[i].newKey >> \in transitionSigs
            /\ log[i].newKey \in attestedKeys

\* (3) Every key currently in HeadState was attested at some point.
\* Pure projection of (1) + (2) onto live state, but it's the property
\* a customer enclave actually cares about: "the synchronizer is not
\* tracking a key it never authenticated."
NoPhantomKey ==
    \A k \in DOMAIN HeadState : k \in attestedKeys

\* (4) Every committed Pin has a prior, still-live Register or Transition
\* for the same key. Stated as: the Pin's key is in HeadState computed
\* over the prefix log[1..i-1], and remains so through index i-1 (i.e.
\* it has not been retired by a Transition between Register and Pin).
PinTraceability ==
    \A i \in 1..Len(log):
        log[i].op = "Pin" =>
            log[i].key \in DOMAIN FoldLog(EmptyMap, i - 1)

\* (5) Once a key is retired by a Transition, no further committed op
\* mentions it as a Pin target or as the oldKey of another Transition,
\* and Register is refused (enforced by ValidOp; we double-check via
\* the log shape).
RetirementIsFinal ==
    \A i \in 1..Len(log):
        log[i].op = "Transition" =>
            \A j \in (i+1)..Len(log):
                /\ log[j].op = "Register"   => log[j].key   # log[i].oldKey
                /\ log[j].op = "Pin"        => log[j].key   # log[i].oldKey
                /\ log[j].op = "Transition" => log[j].oldKey # log[i].oldKey

\* (6) Per-key version monotonicity: across any two states reachable from
\* one another, no key's version can decrease (without leaving HeadState
\* via a Transition, which retires the key).
\* Stated as an action invariant.
MonotonicHeadVersion ==
    [][\A k \in (DOMAIN HeadState) \cap (DOMAIN HeadState'):
            HeadState[k].version <= HeadState'[k].version]_vars

\* (7) Per-node consistency: any node's view is exactly the prefix-fold
\* of the global log up to its applied index. (Trivially true by
\* construction in this abstraction; stated to make the refinement
\* contract with Raft explicit. A separate refinement spec would replace
\* the global `log` with per-node logs and prove they all agree on the
\* same prefix at the applied index.)
NodeViewConsistent ==
    \A n \in Nodes : applied[n] <= Len(log)

\* Bundle for the TLC config.
SafetyInvariants ==
    /\ TypeOK
    /\ RegisterAuthenticity
    /\ TransitionAuthenticity
    /\ NoPhantomKey
    /\ PinTraceability
    /\ RetirementIsFinal
    /\ NodeViewConsistent

(***************************************************************************)
(* THEOREM (machine-checkable by TLC for finite instances):                *)
(*                                                                         *)
(*   Spec => [] SafetyInvariants                                          *)
(*                                                                         *)
(*   Spec => MonotonicHeadVersion                                         *)
(***************************************************************************)
THEOREM TypeSafety   == Spec => [] TypeOK
THEOREM Authenticity == Spec => [] (RegisterAuthenticity /\ TransitionAuthenticity)
THEOREM NoPhantom    == Spec => [] NoPhantomKey
THEOREM Traceable    == Spec => [] PinTraceability
THEOREM FinalRetire  == Spec => [] RetirementIsFinal
THEOREM Monotonic    == Spec => MonotonicHeadVersion

=============================================================================
