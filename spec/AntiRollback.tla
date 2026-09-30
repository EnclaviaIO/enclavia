---------------------------- MODULE AntiRollback ----------------------------
(***************************************************************************)
(* End-to-end model of Enclavia's storage anti-rollback protocol as it     *)
(* stands in the Train 2 synchronizer release (EnclaviaIO/enclavia branch  *)
(* train2 @ f413b5e). See spec/README.md for the prose specification, the *)
(* trust model and the action -> code mapping table.                       *)
(*                                                                         *)
(* Actors:                                                                 *)
(*   * customer enclave instances (nbd-client boot decision + runtime pin) *)
(*   * the real synchronizer cluster "R": 3 member slots, per-node log     *)
(*     prefixes, quorum (or all-voter) ACK, crash = memory loss, restart = *)
(*     new identity that must be admitted by the leader                    *)
(*   * optionally a second cluster "S" built from the SAME trusted image   *)
(*     and run by the host, and a dev (skip-chain) synchronizer "D"        *)
(*   * the owner (control-key holder): issues upgrade links and            *)
(*     revocations                                                         *)
(*   * the host adversary: every scheduling choice, which disk state and   *)
(*     image to boot, which cluster a session reaches, which link to       *)
(*     replay, node crashes, restarts, extra nodes.                        *)
(*                                                                         *)
(* Disk states are small integers; 0 is the blank device. Every written   *)
(* state has a parent; the host keeps every state ever written (snapshot  *)
(* + restore of the whole disk, LUKS header included).                     *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    Images,             \* image identities (PcrKey abstraction)
    Links,              \* upgrade TEMPLATES the owner may approve: [id, from, to, vf, iss]
                        \* (iss = the issued_at an honest backend stamps)
    IssVals,            \* issued_at values a hostile backend may stamp
    VfVals,             \* extra valid_from values a hostile backend may put in a blind-signed payload
    LinkIds,            \* labels the host may put in the UNSIGNED ChainLink.id
    MaxState,           \* number of disk writes (states 1..MaxState)
    MaxBoot,            \* number of customer enclave instances
    MaxTime,            \* NSM time bound (ticks)
    Tol,                \* valid_from tolerance (ticks), 60 s in the code
    MaxLog,             \* bound on the real cluster's log length
    MaxOps,             \* bound on submissions to any cluster
    MaxInst,            \* synchronizer node instances (1..3 initial)
    MaxDisasters,       \* bound on total resets / re-seeds
    \* ---- design / deployment switches ----
    AckPolicy,          \* "quorum" (Train 2, 91750ff) | "all" (pre-Train 2)
    AllowTotalLoss,     \* host may kill all 3 nodes; discovery then forms a fresh cluster
    Shadow,             \* host runs a second cluster "S" from the trusted image
    DevTrusted,         \* client trusts a dev synchronizer "D" (skip-chain)
    ValidFromGate,      \* Transition refused before valid_from - Tol (fd09cff)
    RevocationMode,     \* "linkhash" (f413b5e) | "watermark" (bd673c2, superseded) | "none" |
                        \* "submit" (link hash checked only in the leader pre-check) |
                        \* "unsigned_id" (keyed by the backend-assigned ChainLink.id)
    HostileBackend,     \* the backend builds the payloads the owner signs, adversarially
    CliChecks,          \* what the self-custody CLI checks before signing a backend-built
                        \* payload: "none" | "revocation" (f413b5e: revocations only,
                        \* check_revocation_target) | "decode" (upgrades too: target, valid_from)
    StrictPayloads,     \* payload types cannot be confused (domain separation or
                        \* unknown fields rejected); FALSE = a polyglot payload decodes as
                        \* both a RevocationPayload and an UpgradePayload
    Reseed,             \* "none" (today) | "current" | "believed" | "any"  (#122)
    ClientVersionCheck, \* client requires PinOk.version = expected + 1 (NOT in code)
    CommitMode,         \* "injective" | "shape" (superblock hash collides across forks)
    SuccessorMustTransition, \* an upgrade-target image never registers fresh (NOT in code)
    ExplicitRegister    \* Register is its own RPC; a Pin on an unknown key is NotFound (NOT in code)

ASSUME AckPolicy \in {"quorum", "all"}
ASSUME RevocationMode \in {"watermark", "linkhash", "none", "submit", "unsigned_id"}
ASSUME CliChecks \in {"none", "revocation", "decode"}
ASSUME Reseed \in {"none", "current", "believed", "any"}
ASSUME CommitMode \in {"injective", "shape"}
ASSUME MaxInst >= 3

States   == 0..MaxState
Boots    == 1..MaxBoot
Inst     == 1..MaxInst
Slots    == 1..3
Clusters == {"R"} \cup (IF Shadow THEN {"S"} ELSE {})
                  \cup (IF DevTrusted THEN {"D"} ELSE {})

(***************************************************************************)
(* Variables                                                               *)
(***************************************************************************)
VARIABLES
    \* ---- real cluster "R": node detail ----
    ns,        \* [Inst -> {"unborn","up","down"}]
    slotOf,    \* [Inst -> Slots]
    cfg,       \* committed voter set (instance ids)
    was,       \* instances that have ever been members (cannot rejoin)
    thinks,    \* instances that believe they are voters
    has,       \* [Inst -> Nat]: length of the prefix of rlog the node holds
    leader,    \* instance id, 0 = none
    rlog,      \* the leader's log (Seq of entries)
    rcommit,   \* Raft commit index
    \* ---- applied synchronizer state, per cluster ----
    cs,        \* [Clusters -> ClusterState]
    \* ---- environment ----
    now,       \* trusted NSM time
    issued,    \* signed upgrade links [id, from, to, vf, iss, tpl]; tpl = the template
               \* the owner approved (0: not approved, a type-confused payload)
    revIssued, \* signed revocations [tgt (the link the owner meant), names (the link
               \* hash it carries), riss (its issued_at)]
    nstate,    \* number of disk states written so far
    parent,    \* [1..MaxState -> States]
    disasters, \* total resets + re-seeds so far
    nid,       \* entry id counter
    \* ---- customer enclave instances ----
    ph,        \* phase
    img,       \* image
    disk,      \* disk state the instance serves
    cl,        \* cluster its session reaches
    ver,       \* CAS expected_version
    pst,       \* disk state being pinned
    pend,      \* id of the entry awaiting a response (0 = none)
    rsp,       \* response delivered by the cluster, not yet consumed
    \* ---- ghosts (history, never read by the protocol) ----
    acked,     \* <<image, state>> pairs whose pin was ACKed to the enclave
    ackIdx,    \* <<index, entry id>> ACKed from cluster R
    revEver,   \* [lk, snap]: a link whose revocation (as the owner meant it) was committed
               \* somewhere, with the written states ACKed at that moment
    violRollback, violStale, violAuth, violRev, violOwner

nodeVars   == << ns, slotOf, cfg, was, thinks, has, leader, rlog, rcommit >>
envVars    == << now, issued, revIssued, nstate, parent, disasters >>
clientVars == << ph, img, disk, cl, ver, pst, pend >>
ghostVars  == << acked, ackIdx, revEver, violRollback, violStale, violAuth, violRev, violOwner >>
vars == << nodeVars, cs, envVars, nid, clientVars, rsp, ghostVars >>

(***************************************************************************)
(* Commitments, ancestry, lineage                                          *)
(***************************************************************************)
RECURSIVE Depth(_)
Depth(s) == IF s = 0 THEN 0 ELSE 1 + Depth(parent[s])

\* The pinned value: SHA-256 of the superblock region. "injective" treats it
\* as identifying the whole filesystem state; "shape" is the what-if where
\* two forks that wrote the same amount at the same generation produce
\* byte-identical superblocks (identical bytenr/generation, no content hash).
Com(s) == IF CommitMode = "injective" THEN s ELSE Depth(s)

RECURSIVE Anc(_)
Anc(s) == IF s = 0 THEN {} ELSE {parent[s]} \cup Anc(parent[s])

\* b extends a (b = a or a is an ancestor of b).
Desc(a, b) == a = b \/ a \in Anc(b)

\* Built as an upgrade target (the builder knows this when it builds the
\* staged image, so it could be baked into the measured config).
IsSuccessor(i) == \E t \in Links : t.to = i

\* Images connected to i by signed upgrade links (the customer's lineage).
Linked(i, j) == \E l \in issued : {l.from, l.to} = {i, j}
Lineage(i) == {i} \cup {j \in Images : Linked(i, j)}
              \cup {k \in Images : \E j \in Images : Linked(i, j) /\ Linked(j, k)}

(***************************************************************************)
(* The pure core (synchronizer/src/lib.rs StateMachine::apply)             *)
(***************************************************************************)
NoKey == [reg |-> FALSE, com |-> 0, ver |-> 0]
NoLink == [id |-> 0, from |-> "-", to |-> "-", vf |-> 0, iss |-> 0, tpl |-> 0]

\* Per-cluster applied state. `wm` is the bd673c2 watermark (superseded), `rl` the set of
\* link hashes named by committed revocations (f413b5e), `rids` the
\* unsigned ids (negative model). `rt` is a GHOST: the links the owner MEANT
\* to revoke with the committed revocations, whatever the payload said.
EmptyCS == [k |-> [i \in Images |-> NoKey], ret |-> {},
            wm |-> [i \in Images |-> -1], rl |-> {}, rids |-> {}, rt |-> {}]

Resp(kind, v) == [kind |-> kind, ver |-> v]
NoRsp == [has |-> FALSE, r |-> Resp("None", 0), idx |-> 0, sv |-> FALSE, ov |-> FALSE]

RevokedAtApply(s, e) ==
    CASE RevocationMode = "watermark"   -> s.wm[e.key] >= e.iss
      [] RevocationMode = "linkhash"    -> e.lk \in s.rl
      [] RevocationMode = "unsigned_id" -> e.rid \in s.rids
      [] OTHER                          -> FALSE

ApplyE(s, e) ==
  CASE e.kind = "Reg" ->
         IF e.key \in s.ret THEN [s |-> s, r |-> Resp("Rejected", 0)]
         ELSE IF s.k[e.key].reg THEN [s |-> s, r |-> Resp("AlreadyReg", 0)]
         ELSE [s |-> [s EXCEPT !.k[e.key] = [reg |-> TRUE, com |-> e.com, ver |-> 0]],
               r |-> Resp("Ok", 0)]
    [] e.kind = "Pin" ->
         IF ~s.k[e.key].reg THEN [s |-> s, r |-> Resp("NotFound", 0)]
         ELSE IF s.k[e.key].ver # e.ev
              THEN [s |-> s, r |-> Resp("Conflict", s.k[e.key].ver)]
         ELSE [s |-> [s EXCEPT !.k[e.key] = [reg |-> TRUE, com |-> e.com,
                                             ver |-> s.k[e.key].ver + 1]],
               r |-> Resp("Ok", s.k[e.key].ver + 1)]
    [] e.kind = "Trans" ->
         IF \/ e.key = e.new \/ ~s.k[e.key].reg \/ s.k[e.new].reg \/ e.new \in s.ret
         THEN [s |-> s, r |-> Resp("Rejected", 0)]
         ELSE IF RevokedAtApply(s, e) THEN [s |-> s, r |-> Resp("Revoked", 0)]
         ELSE [s |-> [s EXCEPT !.k = [i \in Images |->
                                        IF i = e.new THEN s.k[e.key]
                                        ELSE IF i = e.key THEN NoKey
                                        ELSE s.k[i]],
                               !.ret = s.ret \cup {e.key}],
               r |-> Resp("Ok", s.k[e.key].ver)]
    [] OTHER -> \* "Rev"
         IF e.key \in s.ret \/ ~s.k[e.key].reg THEN [s |-> s, r |-> Resp("Rejected", 0)]
         ELSE [s |-> [s EXCEPT !.wm[e.key] = IF s.wm[e.key] < e.iss THEN e.iss
                                             ELSE s.wm[e.key],
                               !.rl = s.rl \cup {e.lk},
                               !.rids = s.rids \cup {e.rid},
                               !.rt = s.rt \cup {e.tgt}],
               r |-> Resp("Ok", 0)]

RECURSIVE FoldCS(_, _)
FoldCS(sq, n) == IF n = 0 THEN EmptyCS ELSE ApplyE(FoldCS(sq, n - 1), sq[n]).s

\* Templates the owner approved (confirmed) so far.
Approved == {l.tpl : l \in issued} \ {0}
Tpl(id) == CHOOSE t \in Links : t.id = id

\* A transition is what the owner authorized: its link came from a template
\* the owner approved, it moves to that template's target, the leader's NSM
\* time had reached the template's valid_from (minus tolerance), and no
\* revocation the owner meant for this link was committed before it in this
\* cluster's history.
OwnerAuthorized(s, e) ==
    /\ e.lk.tpl \in Approved
    /\ Tpl(e.lk.tpl).from = e.key /\ Tpl(e.lk.tpl).to = e.new
    /\ e.t + Tol >= Tpl(e.lk.tpl).vf
    /\ e.lk \notin s.rt

\* Ghost bookkeeping for one applied entry (s = state before, res = result).
GhostApply(s, e, res) ==
    /\ violAuth' = (violAuth \/
          (e.kind = "Trans" /\ res.r.kind = "Ok" /\ ~ OwnerAuthorized(s, e)))
    \* 0 = never; 1 = a revoked link moved a pin; 2 = the pin it moved covers
    \* data derived from a written state the lineage had ACKed when the
    \* revocation committed (the owner's real data, not a fresh volume).
    /\ violRev' = IF /\ e.kind = "Trans" /\ res.r.kind = "Ok"
                     /\ \E r \in revEver : r.lk = e.lk
                  THEN IF \/ violRev = 2
                          \/ \E r \in revEver :
                                /\ r.lk = e.lk
                                /\ \E a \in r.snap : a # 0 /\ CommitMode = "injective"
                                                   /\ Desc(a, s.k[e.key].com)
                       THEN 2 ELSE 1
                  ELSE violRev
    /\ violOwner' = (violOwner \/
          (e.kind \in {"Reg", "Pin"} /\ res.r.kind = "Ok" /\ e.by = "adv"))
    /\ revEver' = IF e.kind = "Rev" /\ res.r.kind = "Ok"
                  THEN revEver \cup {[lk |-> e.tgt, snap |-> {p[2] : p \in acked}]}
                  ELSE revEver

(***************************************************************************)
(* Real cluster helpers                                                    *)
(***************************************************************************)
Up(i) == ns[i] = "up"
UpVoters == {v \in cfg : Up(v)}
Majority(S, T) == 2 * Cardinality(S) > Cardinality(T)
RAvail == /\ leader # 0 /\ Up(leader) /\ leader \in cfg
          /\ Majority(UpVoters, cfg)
Avail(c) == IF c = "R" THEN RAvail ELSE TRUE

(***************************************************************************)
(* Serving check (NoRollback) and submission helper                        *)
(***************************************************************************)
StaleVs(x, s) == \E p \in acked : p[1] \in Lineage(img[x]) /\ ~ Desc(p[2], s)

\* s is an OLDER version of data the lineage already had ACKed.
OlderThanAcked(x, s) == \E p \in acked : p[1] \in Lineage(img[x]) /\ s \in Anc(p[2])

ServeCheck(x, s) ==
    /\ violRollback' = (violRollback \/ StaleVs(x, s))
    /\ violStale'    = (violStale \/ (s # 0 /\ OlderThanAcked(x, s)))

\* A response, with the serve check evaluated at the operation's
\* linearization point (commit), not at delivery: an instance's view is as of
\* its last linearized operation (the accepted stale-read window).
MkRsp(x, r, idx) == [has |-> TRUE, r |-> r, idx |-> idx, sv |-> StaleVs(x, disk[x]),
                     ov |-> (disk[x] # 0 /\ OlderThanAcked(x, disk[x]))]

\* Submit entry e to cluster c on behalf of instance x (0 = no response wanted).
\* R: append to the leader's log; the response comes at commit.
\* S / D: host-run clusters, modeled as atomic stores.
Submit(c, e, x) ==
    /\ nid < MaxOps
    /\ nid' = nid + 1
    /\ IF c = "R"
       THEN /\ RAvail /\ Len(rlog) < MaxLog
            /\ rlog' = Append(rlog, e)
            /\ has' = [has EXCEPT ![leader] = @ + 1]
            /\ rsp' = IF x = 0 THEN rsp ELSE [rsp EXCEPT ![x] = NoRsp]
            /\ UNCHANGED << cs, revEver, violAuth, violRev, violOwner >>
       ELSE LET res == ApplyE(cs[c], e) IN
            /\ cs' = [cs EXCEPT ![c] = res.s]
            /\ GhostApply(cs[c], e, res)
            /\ rsp' = IF x = 0 THEN rsp
                      ELSE [rsp EXCEPT ![x] = MkRsp(x, res.r, 0)]
            /\ UNCHANGED << rlog, has >>

EntryL(kind, key, new, com, ev, iss, rid, by, lk, tgt) ==
    [id |-> nid + 1, kind |-> kind, key |-> key, new |-> new, com |-> com,
     ev |-> ev, iss |-> iss, rid |-> rid, t |-> now, by |-> by, lk |-> lk, tgt |-> tgt]

Entry(kind, key, new, com, ev, iss, rid, by) ==
    EntryL(kind, key, new, com, ev, iss, rid, by, NoLink, NoLink)

(***************************************************************************)
(* Init                                                                    *)
(***************************************************************************)
Init ==
    /\ ns = [i \in Inst |-> IF i <= 3 THEN "up" ELSE "unborn"]
    /\ slotOf = [i \in Inst |-> IF i <= 3 THEN i ELSE 1]
    /\ cfg = {1, 2, 3}
    /\ was = {1, 2, 3}
    /\ thinks = {1, 2, 3}
    /\ has = [i \in Inst |-> 0]
    /\ leader = 1
    /\ rlog = << >>
    /\ rcommit = 0
    /\ cs = [c \in Clusters |-> EmptyCS]
    /\ now = 0
    /\ issued = {}
    /\ revIssued = {}
    /\ nstate = 0
    /\ parent = [s \in 1..MaxState |-> 0]
    /\ disasters = 0
    /\ nid = 0
    /\ ph = [x \in Boots |-> "off"]
    /\ img = [x \in Boots |-> CHOOSE i \in Images : TRUE]
    /\ disk = [x \in Boots |-> 0]
    /\ cl = [x \in Boots |-> "R"]
    /\ ver = [x \in Boots |-> 0]
    /\ pst = [x \in Boots |-> 0]
    /\ pend = [x \in Boots |-> 0]
    /\ rsp = [x \in Boots |-> NoRsp]
    /\ acked = {}
    /\ ackIdx = {}
    /\ revEver = {}
    /\ violRollback = FALSE
    /\ violStale = FALSE
    /\ violAuth = FALSE
    /\ violRev = 0
    /\ violOwner = FALSE

(***************************************************************************)
(* Owner and time                                                          *)
(***************************************************************************)
Tick == /\ now < MaxTime /\ now' = now + 1
        /\ UNCHANGED << nodeVars, cs, issued, revIssued, nstate, parent, disasters,
                        nid, clientVars, rsp, ghostVars >>

\* Confirming an upgrade. The BACKEND builds the UpgradePayload (enclavia-
\* backend build_upgrade_payload); the control-key holder signs it (managed
\* custody: the backend itself; self-hosted: the CLI signs the bytes it is
\* handed, enclavia-cli signer.rs sign_confirm_submission). The old enclave
\* then emits the link; it is public (chain) and the host keeps it.
\*   honest backend:           the payload is the template.
\*   hostile, CLI "decode":    only issued_at is free (the CLI cannot check it).
\*   hostile, CLI "none" or "revocation" (f413b5e): to, valid_from and
\*                             issued_at are all free.
Issue(t, to, vf, iss) ==
    /\ t.id \notin Approved
    /\ IF ~ HostileBackend THEN to = t.to /\ vf = t.vf /\ iss = t.iss
       ELSE IF CliChecks = "decode" THEN to = t.to /\ vf = t.vf
       ELSE TRUE
    /\ issued' = issued \cup {[id |-> t.id, from |-> t.from, to |-> to, vf |-> vf,
                               iss |-> iss, tpl |-> t.id]}
    /\ UNCHANGED << nodeVars, cs, now, revIssued, nstate, parent, disasters,
                    nid, clientVars, rsp, ghostVars >>

\* Revoking an upgrade the owner confirmed (only before its valid_from: the
\* backend refuses later, upgrades.rs revoke). The backend builds the
\* RevocationPayload; the owner signs it.
\*   names: the link hash the payload carries (revokes_link, f413b5e);
\*          NoLink = a hash of no signed link at all;
\*   riss:  its issued_at (only the superseded bd673c2 watermark reads it).
\* With StrictPayloads = FALSE a hostile backend can make the signed bytes a
\* polyglot that ALSO decodes as an UpgradePayload out of the same key (serde
\* ignores unknown fields); the old enclave attests those bytes when it
\* processes the revoke, so they become a usable upgrade link (tpl = 0).
IssueRevoke(L, names, riss, pto, pvf, piss) ==
    /\ L \in issued /\ L.tpl # 0 /\ now < Tpl(L.tpl).vf
    /\ ~ \E r \in revIssued : r.tgt = L
    /\ IF ~ HostileBackend THEN names = L /\ riss = L.iss
       ELSE IF CliChecks \in {"revocation", "decode"} THEN names = L
       ELSE TRUE
    /\ revIssued' = revIssued \cup {[tgt |-> L, names |-> names, riss |-> riss]}
    /\ issued' = IF HostileBackend /\ ~ StrictPayloads
                 THEN issued \cup {[id |-> 0, from |-> L.from, to |-> pto, vf |-> pvf,
                                    iss |-> piss, tpl |-> 0]}
                 ELSE issued
    /\ UNCHANGED << nodeVars, cs, now, nstate, parent, disasters,
                    nid, clientVars, rsp, ghostVars >>

(***************************************************************************)
(* Customer enclave: boot (nbd-client/src/rollback.rs verify_or_register)  *)
(***************************************************************************)
\* The host boots any image with any disk state it holds, and its relay
\* decides which cluster the session reaches.
Boot(x, i, s, c) ==
    /\ ph[x] = "off" /\ (IF x = 1 THEN TRUE ELSE ph[x - 1] # "off")
    /\ ph' = [ph EXCEPT ![x] = "get"]
    /\ img' = [img EXCEPT ![x] = i]
    /\ disk' = [disk EXCEPT ![x] = s]
    /\ cl' = [cl EXCEPT ![x] = c]
    /\ UNCHANGED << nodeVars, cs, envVars, nid, ver, pst, pend, rsp, ghostVars >>

\* Boot-time linearizable Get + decision table.
BootGet(x) ==
    /\ ph[x] = "get" /\ Avail(cl[x])
    /\ LET k == cs[cl[x]].k[img[x]] IN
       IF k.reg
       THEN IF Com(disk[x]) = k.com
            THEN /\ ph' = [ph EXCEPT ![x] = "srv"]          \* Serve
                 /\ ver' = [ver EXCEPT ![x] = k.ver]
                 /\ ServeCheck(x, disk[x])
            ELSE /\ ph' = [ph EXCEPT ![x] = "dead"]         \* FailStop (mismatch)
                 /\ UNCHANGED << ver, violRollback, violStale >>
       ELSE IF disk[x] = 0 /\ ~ (SuccessorMustTransition /\ IsSuccessor(img[x]))
            THEN /\ ph' = [ph EXCEPT ![x] = "reg"]          \* RegisterThenServe
                 /\ UNCHANGED << ver, violRollback, violStale >>
            ELSE /\ ph' = [ph EXCEPT ![x] = "trans"]        \* TransitionOrFailStop
                 /\ UNCHANGED << ver, violRollback, violStale >>
    /\ UNCHANGED << nodeVars, cs, envVars, nid, img, disk, cl, pst, pend, rsp,
                    acked, ackIdx, revEver, violAuth, violRev, violOwner >>


\* Variables Submit(...) may touch: nid, rlog, has, cs, rsp, revEver,
\* violAuth, violRev, violOwner. Callers leave everything else unchanged.
SubmitFrame == << ns, slotOf, cfg, was, thinks, leader, rcommit, envVars,
                  acked, ackIdx, violRollback, violStale >>
\* Variables no protocol step other than Submit / AdvanceR touches.
NoSubmit == << nid, rlog, has, cs, revEver, violAuth, violRev, violOwner >>

\* Registration: nbd-client sends Pin(expected_version 0); the server maps it
\* to Register when its local state says the key is unknown, else to a CAS
\* Pin (serve.rs handle_pin).
BootRegister(x) ==
    /\ ph[x] = "reg" /\ pend[x] = 0 /\ Avail(cl[x])
    /\ LET e == IF cs[cl[x]].k[img[x]].reg /\ ~ ExplicitRegister
                THEN Entry("Pin", img[x], img[x], Com(0), 0, 0, 0, "enc")
                ELSE Entry("Reg", img[x], img[x], Com(0), 0, 0, 0, "enc")
       IN /\ Submit(cl[x], e, x)
          /\ pend' = [pend EXCEPT ![x] = e.id]
    /\ UNCHANGED << SubmitFrame, ph, img, disk, cl, ver, pst >>

\* Written superblock + unknown key: the host serves an upgrade link from
\* chain-host (any link it has ever seen; rid is the unsigned ChainLink.id
\* label it attaches). The leader pre-checks against its applied state
\* (serve.rs handle_transition): old key live (frozen pubkey lookup), link
\* signed, new key = session key, valid_from gate on NSM time.
TransOk(c, l) ==
    /\ cs[c].k[l.from].reg
    /\ (ValidFromGate => now + Tol >= l.vf)
    /\ ~ (RevocationMode = "submit" /\ l \in cs[c].rl)

BootTransition(x, l, rid) ==
    /\ ph[x] = "trans" /\ pend[x] = 0 /\ Avail(cl[x])
    /\ l \in issued /\ l.to = img[x]
    /\ IF TransOk(cl[x], l)
       THEN LET e == EntryL("Trans", l.from, l.to, 0, 0, l.iss, rid, "enc", l, NoLink) IN
            /\ Submit(cl[x], e, x)
            /\ pend' = [pend EXCEPT ![x] = e.id]
            /\ UNCHANGED << SubmitFrame, ph, img, disk, cl, ver, pst >>
       ELSE /\ ph' = [ph EXCEPT ![x] = "dead"]   \* TransitionRejected: fail-stop
            /\ UNCHANGED << nodeVars, cs, envVars, nid, img, disk, cl, ver, pst, pend,
                            rsp, ghostVars >>

\* AlreadyRegistered during registration: the server retries once as a CAS
\* Pin with the caller's expected_version (0) (serve.rs handle_pin).
RegRetryAsPin(x) ==
    /\ ph[x] = "regpin" /\ Avail(cl[x])
    /\ LET e == Entry("Pin", img[x], img[x], Com(0), 0, 0, 0, "enc") IN
       /\ Submit(cl[x], e, x)
       /\ pend' = [pend EXCEPT ![x] = e.id]
    /\ ph' = [ph EXCEPT ![x] = "reg"]
    /\ UNCHANGED << SubmitFrame, img, disk, cl, ver, pst >>

\* Post-Transition Get: the carried commitment must match the disk.
Get2(x) ==
    /\ ph[x] = "get2" /\ Avail(cl[x])
    /\ LET k == cs[cl[x]].k[img[x]] IN
       IF k.reg /\ Com(disk[x]) = k.com
       THEN /\ ph' = [ph EXCEPT ![x] = "srv"]
            /\ ver' = [ver EXCEPT ![x] = k.ver]
            /\ ServeCheck(x, disk[x])
       ELSE /\ ph' = [ph EXCEPT ![x] = "dead"]
            /\ UNCHANGED << ver, violRollback, violStale >>
    /\ UNCHANGED << nodeVars, cs, envVars, nid, img, disk, cl, pst, pend, rsp,
                    acked, ackIdx, revEver, violAuth, violRev, violOwner >>

(***************************************************************************)
(* Customer enclave: runtime pinning (SyncPinner, pin_with_retries)        *)
(***************************************************************************)
\* A superblock write: the host sees the new ciphertext before the pin (the
\* write is forwarded first), so every written state is in the host's hands.
Write(x) ==
    /\ ph[x] = "srv" /\ nstate < MaxState
    /\ nstate' = nstate + 1
    /\ parent' = [parent EXCEPT ![nstate + 1] = disk[x]]
    /\ pst' = [pst EXCEPT ![x] = nstate + 1]
    /\ ph' = [ph EXCEPT ![x] = "pin"]
    /\ pend' = [pend EXCEPT ![x] = 0]
    /\ UNCHANGED << nodeVars, cs, now, issued, revIssued, disasters, nid, img, disk,
                    cl, ver, rsp, ghostVars >>

\* Pin RPC (also every retry). Wire Pin; the server maps an unknown key to
\* Register, ignoring expected_version (serve.rs handle_pin).
PinSubmit(x) ==
    /\ ph[x] = "pin" /\ pend[x] = 0 /\ Avail(cl[x])
    /\ LET e == IF cs[cl[x]].k[img[x]].reg \/ ExplicitRegister
                THEN Entry("Pin", img[x], img[x], Com(pst[x]), ver[x], 0, 0, "enc")
                ELSE Entry("Reg", img[x], img[x], Com(pst[x]), 0, 0, 0, "enc")
       IN /\ Submit(cl[x], e, x)
          /\ pend' = [pend EXCEPT ![x] = e.id]
    /\ UNCHANGED << SubmitFrame, ph, img, disk, cl, ver, pst >>

\* RPC timeout / lost response: retry (at-least-once).
PinTimeout(x) ==
    /\ ph[x] = "pin" /\ pend[x] # 0
    /\ pend' = [pend EXCEPT ![x] = 0]
    /\ rsp' = [rsp EXCEPT ![x] = NoRsp]
    /\ UNCHANGED << nodeVars, cs, envVars, nid, ph, img, disk, cl, ver, pst, ghostVars >>

\* The host drops the session; the client re-dials through the host relay
\* (fresh handshake + mutual attestation, no boot re-verification) and the
\* host chooses which cluster answers (into_pinner / connect_and_authenticate).
Reconnect(x, c) ==
    /\ ph[x] \in {"srv", "pin"} /\ c # cl[x]
    /\ cl' = [cl EXCEPT ![x] = c]
    /\ pend' = [pend EXCEPT ![x] = 0]
    /\ rsp' = [rsp EXCEPT ![x] = NoRsp]
    /\ UNCHANGED << nodeVars, cs, envVars, nid, ph, img, disk, ver, pst, ghostVars >>

\* VersionConflict disambiguation Get (disambiguate_conflict).
Disambiguate(x) ==
    /\ ph[x] = "dis" /\ Avail(cl[x])
    /\ LET k == cs[cl[x]].k[img[x]] IN
       IF k.reg /\ k.com = Com(pst[x])
       THEN /\ ph' = [ph EXCEPT ![x] = "srv"]
            /\ ver' = [ver EXCEPT ![x] = k.ver]
            /\ disk' = [disk EXCEPT ![x] = pst[x]]
            /\ acked' = acked \cup {<< img[x], pst[x] >>}
       ELSE /\ ph' = [ph EXCEPT ![x] = "dead"]
            /\ UNCHANGED << ver, disk, acked >>
    /\ UNCHANGED << nodeVars, cs, envVars, nid, img, cl, pst, pend, rsp,
                    ackIdx, revEver, violRollback, violStale, violAuth, violRev, violOwner >>

\* The old enclave commits the owner's revocation over its own session
\* (enclavia-server sync_revoke; requires the key live and the session
\* attested as that key). The host decides when (or whether) it arrives.
SubmitRevoke(x, r) ==
    /\ ph[x] = "srv" /\ img[x] = r.tgt.from /\ r \in revIssued /\ Avail(cl[x])
    /\ cs[cl[x]].k[r.tgt.from].reg
    /\ Submit(cl[x], EntryL("Rev", r.tgt.from, r.tgt.from, 0, 0, r.riss, r.tgt.id, "enc",
                            r.names, r.tgt), 0)
    /\ UNCHANGED << SubmitFrame, clientVars >>

(***************************************************************************)
(* Delivering a response to the enclave                                    *)
(***************************************************************************)
AckReady(x) == \/ cl[x] # "R"
               \/ AckPolicy = "quorum"
               \/ \A v \in cfg : has[v] >= rsp[x].idx

Deliver(x) ==
    /\ rsp[x].has /\ AckReady(x)
    /\ LET r == rsp[x].r
           ackR == IF cl[x] = "R" THEN ackIdx \cup {<< rsp[x].idx, pend[x] >>} ELSE ackIdx
       IN CASE ph[x] = "reg" ->
                 IF r.kind = "Ok" /\ r.ver = 0
                 THEN /\ ph' = [ph EXCEPT ![x] = "srv"]
                      /\ ver' = [ver EXCEPT ![x] = 0]
                      /\ acked' = acked \cup {<< img[x], disk[x] >>}
                      /\ ackIdx' = ackR
                      /\ violRollback' = (violRollback \/ rsp[x].sv)
                      /\ violStale' = (violStale \/ rsp[x].ov)
                      /\ UNCHANGED << disk >>
                 ELSE /\ ph' = [ph EXCEPT ![x] = IF r.kind = "AlreadyReg" /\ ~ ExplicitRegister THEN "regpin" ELSE "dead"]
                      /\ UNCHANGED << ver, disk, acked, ackIdx, violRollback, violStale >>
            [] ph[x] = "trans" ->
                 /\ ph' = [ph EXCEPT ![x] = IF r.kind = "Ok" THEN "get2" ELSE "dead"]
                 /\ UNCHANGED << ver, disk, acked, ackIdx, violRollback, violStale >>
            [] ph[x] = "pin" ->
                 IF r.kind = "Ok" /\ ~ (ClientVersionCheck /\ r.ver # ver[x] + 1)
                 THEN /\ ph' = [ph EXCEPT ![x] = "srv"]
                      /\ ver' = [ver EXCEPT ![x] = r.ver]
                      /\ disk' = [disk EXCEPT ![x] = pst[x]]
                      /\ acked' = acked \cup {<< img[x], pst[x] >>}
                      /\ ackIdx' = ackR
                      /\ UNCHANGED << violRollback, violStale >>
                 ELSE /\ ph' = [ph EXCEPT ![x] = CASE r.kind = "Conflict"   -> "dis"
                                                  [] r.kind = "AlreadyReg" -> "pin"
                                                  [] OTHER                 -> "dead"]
                      /\ UNCHANGED << ver, disk, acked, ackIdx, violRollback, violStale >>
            [] OTHER ->
                 UNCHANGED << ph, ver, disk, acked, ackIdx, violRollback, violStale >>
    /\ rsp' = [rsp EXCEPT ![x] = NoRsp]
    /\ pend' = [pend EXCEPT ![x] = 0]
    /\ UNCHANGED << nodeVars, cs, envVars, nid, img, cl, pst,
                    revEver, violAuth, violRev, violOwner >>

(***************************************************************************)
(* Real cluster R: replication, commit, crashes, admission, elections      *)
(***************************************************************************)
Replicate(i) ==
    /\ Up(i) /\ i \in cfg /\ i # leader /\ leader # 0 /\ Up(leader)
    /\ has[i] < Len(rlog)
    /\ has' = [has EXCEPT ![i] = @ + 1]
    /\ UNCHANGED << ns, slotOf, cfg, was, thinks, leader, rlog, rcommit, cs, envVars,
                    nid, clientVars, rsp, ghostVars >>

\* Raft commit: the leader counts a majority of the voter set holding the
\* entry. The pure core applies it on every replica identically.
AdvanceR ==
    /\ leader # 0 /\ Up(leader) /\ leader \in cfg
    /\ rcommit < Len(rlog)
    /\ Majority({v \in cfg : has[v] > rcommit}, cfg)
    /\ LET e == rlog[rcommit + 1]
           res == ApplyE(cs["R"], e)
       IN /\ rcommit' = rcommit + 1
          /\ cs' = [cs EXCEPT !["R"] = res.s]
          /\ GhostApply(cs["R"], e, res)
          /\ rsp' = [x \in Boots |->
                       IF cl[x] = "R" /\ pend[x] = e.id
                       THEN MkRsp(x, res.r, rcommit + 1)
                       ELSE rsp[x]]
    /\ UNCHANGED << ns, slotOf, cfg, was, thinks, has, leader, rlog, envVars, nid,
                    clientVars, acked, ackIdx, violRollback, violStale >>

\* A node crash loses its whole memory (no persistence). Without
\* AllowTotalLoss the documented operational precondition holds: never lose
\* every voter at once.
Crash(i) ==
    /\ Up(i)
    /\ AllowTotalLoss \/ \E v \in cfg \ {i} : Up(v)
    /\ ns' = [ns EXCEPT ![i] = "down"]
    /\ has' = [has EXCEPT ![i] = 0]
    /\ thinks' = thinks \ {i}
    /\ leader' = IF leader = i THEN 0 ELSE leader
    /\ UNCHANGED << slotOf, cfg, was, rlog, rcommit, cs, envVars, nid, clientVars,
                    rsp, ghostVars >>

\* A restart is a NEW instance (per-boot identity, #209) for some slot. The
\* host may also start one while the slot's current holder is alive (clone).
Start(i, s) ==
    /\ ns[i] = "unborn"
    /\ ns' = [ns EXCEPT ![i] = "up"]
    /\ slotOf' = [slotOf EXCEPT ![i] = s]
    /\ UNCHANGED << cfg, was, thinks, has, leader, rlog, rcommit, cs, envVars, nid,
                    clientVars, rsp, ghostVars >>

\* Leader-side admission (RaftHandle::admit): add_learner (catch up to the
\* leader's log), then change_membership replacing the slot's holder.
Admit(i) ==
    /\ Up(i) /\ i \notin was /\ RAvail
    /\ LET old == {m \in cfg : slotOf[m] = slotOf[i]} IN
       /\ leader \notin old
       /\ cfg' = (cfg \ old) \cup {i}
    /\ was' = was \cup {i}
    /\ thinks' = thinks \cup {i}
    /\ has' = [has EXCEPT ![i] = Len(rlog)]
    /\ UNCHANGED << ns, slotOf, leader, rlog, rcommit, cs, envVars, nid, clientVars,
                    rsp, ghostVars >>

\* An evicted-but-alive instance learns it was replaced (watch_for_eviction).
\* Until then (e.g. while the host partitions it) it believes it is a voter.
LearnEviction(i) ==
    /\ Up(i) /\ i \in thinks /\ i \notin cfg
    /\ thinks' = thinks \ {i}
    /\ UNCHANGED << ns, slotOf, cfg, was, has, leader, rlog, rcommit, cs, envVars, nid,
                    clientVars, rsp, ghostVars >>

\* Election after the leader died. ASSUMPTION (openraft): the winner holds
\* every committed entry; modeled as the up voter with the longest log, and
\* checked by the LeaderCompleteness invariant. Uncommitted suffixes beyond
\* the winner's log are discarded.
Elect(l) ==
    /\ leader = 0 /\ Majority(UpVoters, cfg)
    /\ l \in UpVoters
    /\ \A v \in UpVoters : has[v] <= has[l]
    /\ leader' = l
    /\ rlog' = SubSeq(rlog, 1, has[l])
    /\ has' = [i \in Inst |-> IF has[i] > has[l] THEN has[l] ELSE has[i]]
    /\ UNCHANGED << ns, slotOf, cfg, was, thinks, rcommit, cs, envVars, nid,
                    clientVars, rsp, ghostVars >>

\* Clients whose session was on R lose any pending response.
DropRSessions ==
    /\ pend' = [x \in Boots |-> IF cl[x] = "R" THEN 0 ELSE pend[x]]
    /\ rsp' = [x \in Boots |-> IF cl[x] = "R" THEN NoRsp ELSE rsp[x]]

\* The host kills all three nodes and restarts them. Every restarted node
\* answers NoCluster, so the smallest name initializes a fresh, EMPTY cluster
\* (join.rs discover_and_join). Cold start is out of scope for AckDurability
\* (its ACK ledger is reset here), but NOT for the end-to-end properties.
TotalReset ==
    /\ AllowTotalLoss /\ disasters < MaxDisasters
    /\ disasters' = disasters + 1
    /\ ns' = [i \in Inst |-> IF i <= 3 THEN "up" ELSE IF ns[i] = "unborn" THEN "unborn" ELSE "down"]
    /\ slotOf' = [i \in Inst |-> IF i <= 3 THEN i ELSE slotOf[i]]
    /\ cfg' = {1, 2, 3}
    /\ was' = was \cup {1, 2, 3}
    /\ thinks' = {1, 2, 3}
    /\ has' = [i \in Inst |-> 0]
    /\ leader' = 1
    /\ rlog' = << >>
    /\ rcommit' = 0
    /\ cs' = [cs EXCEPT !["R"] = EmptyCS]
    /\ ackIdx' = {}
    /\ DropRSessions
    /\ UNCHANGED << now, issued, revIssued, nstate, parent, nid, ph, img, disk, cl, ver,
                    pst, acked, revEver, violRollback, violStale, violAuth, violRev,
                    violOwner >>

\* #122-style re-seed (NOT implemented today): with the cluster halted (no
\* majority of voters up), the operator re-seeds a cluster from one surviving
\* node's state. "current": the survivor is a voter of the committed config
\* (oracle knowledge); "believed": the survivor believes it is a voter (what
\* the node itself can report); "any": any surviving node.
ReseedFrom(s) ==
    /\ Reseed # "none" /\ disasters < MaxDisasters
    /\ ~ Majority(UpVoters, cfg)
    /\ Up(s)
    /\ CASE Reseed = "current"  -> s \in cfg
         [] Reseed = "believed" -> s \in thinks
         [] OTHER               -> TRUE
    /\ disasters' = disasters + 1
    /\ rlog' = SubSeq(rlog, 1, has[s])
    /\ rcommit' = has[s]
    /\ cs' = [cs EXCEPT !["R"] = FoldCS(rlog', has[s])]
    /\ cfg' = {s}
    /\ was' = was \cup {s}
    /\ thinks' = {s}
    /\ leader' = s
    /\ has' = [i \in Inst |-> IF i = s THEN has[s] ELSE 0]
    /\ DropRSessions
    /\ UNCHANGED << ns, slotOf, now, issued, revIssued, nstate, parent, nid, ph, img, disk,
                    cl, ver, pst, acked, ackIdx, revEver, violRollback, violStale,
                    violAuth, violRev, violOwner >>

(***************************************************************************)
(* Dev synchronizer D: skips certificate-chain verification, so the host   *)
(* can open sessions attested as ANY key and pin whatever it likes.        *)
(***************************************************************************)
AdvPinD(i, s) ==
    /\ DevTrusted
    /\ LET k == cs["D"].k[i]
           e == IF k.reg THEN Entry("Pin", i, i, Com(s), k.ver, 0, 0, "adv")
                ELSE Entry("Reg", i, i, Com(s), 0, 0, 0, "adv")
       IN Submit("D", e, 0)
    /\ UNCHANGED << SubmitFrame, clientVars >>

(***************************************************************************)
(* Next                                                                    *)
(***************************************************************************)
Next ==
    \/ Tick
    \/ \E t \in Links : \E to \in Images \ {t.from}, vf \in VfVals \cup {t.vf}, iss \in IssVals \cup {t.iss} :
          Issue(t, to, vf, iss)
    \/ \E L \in {l \in issued : l.tpl # 0} : \E N \in issued \cup {NoLink}, riss \in IssVals \cup {L.iss} :
       \E pto \in (IF HostileBackend /\ ~ StrictPayloads THEN Images \ {L.from} ELSE {"-"}),
          pvf \in (IF HostileBackend /\ ~ StrictPayloads THEN VfVals \cup {Tpl(L.tpl).vf} ELSE {0}),
          piss \in (IF HostileBackend /\ ~ StrictPayloads THEN IssVals ELSE {0}) :
            IssueRevoke(L, N, riss, pto, pvf, piss)
    \/ \E x \in Boots, i \in Images, s \in 0..nstate, c \in Clusters : Boot(x, i, s, c)
    \/ \E x \in Boots :
          \/ BootGet(x) \/ BootRegister(x) \/ RegRetryAsPin(x) \/ Get2(x)
          \/ Write(x) \/ PinSubmit(x) \/ PinTimeout(x) \/ Disambiguate(x) \/ Deliver(x)
          \/ \E c \in Clusters : Reconnect(x, c)
          \/ \E r \in revIssued : SubmitRevoke(x, r)
          \/ \E l \in issued : \E rid \in (IF RevocationMode = "unsigned_id" THEN LinkIds ELSE {l.id}) :
                BootTransition(x, l, rid)
    \/ \E i \in Inst : Replicate(i) \/ Crash(i) \/ Admit(i) \/ LearnEviction(i)
                       \/ Elect(i) \/ ReseedFrom(i)
    \/ \E i \in Inst, s \in Slots : Start(i, s)
    \/ AdvanceR
    \/ TotalReset
    \/ \E i \in Images, s \in 0..nstate : AdvPinD(i, s)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* PROPERTIES                                                              *)
(***************************************************************************)
\* An instance never BEGINS serving a disk state that fails to extend a state
\* already ACKed anywhere in its lineage (its image plus every image linked to
\* it by a signed upgrade link). Checked at every serve decision: Serve,
\* RegisterThenServe, post-Transition Get.
NoRollback == ~ violRollback

\* Narrower: an instance never begins serving a written state that is an
\* OLDER version (strict ancestor) of a state already ACKed in its lineage,
\* i.e. the host cannot restore an old snapshot of the enclave's own data.
\* Excludes the blank-volume and divergent-fork cases (NoRollback, NoFork).
NoStaleRestore == ~ violStale

\* ACKed states of a lineage form one chain: no two instances ever get
\* divergent writes acknowledged.
NoFork == \A p, q \in acked : q[1] \in Lineage(p[1]) => (Desc(p[2], q[2]) \/ Desc(q[2], p[2]))

\* A Transition only applies with a link the control key signed, whose
\* valid_from (minus tolerance) the leader's NSM time had reached, and which
\* no revocation committed earlier in the same cluster history covers.
TransitionAuthorized == ~ violAuth

\* Once a revocation is committed ANYWHERE, no Transition with a link it
\* covers ever applies afterwards (in any cluster history).
RevocationPermanent == violRev = 0

\* Weaker: no revoked link ever moves a pin whose data derives from a written
\* state the lineage had ACKed when the revocation committed.
RevocationPermanentData == violRev < 2

\* Only a session attested as key K can register or pin under K.
OwnerOnly == ~ violOwner

\* Every write ACKed by R is still committed at the same log position
\* (survives node loss), unless the whole cluster was re-initialized.
AckDurability == \A p \in ackIdx : /\ p[1] <= rcommit /\ p[1] <= Len(rlog)
                                   /\ rlog[p[1]].id = p[2]

\* Sanity check of the Raft abstraction (not a protocol property).
LeaderCompleteness ==
    /\ rcommit <= Len(rlog)
    /\ \A i \in Inst : has[i] <= Len(rlog)
    /\ (leader # 0 /\ Up(leader)) => has[leader] = Len(rlog)
=============================================================================
