# Formal model of the storage anti-rollback protocol (Train 2)

This directory holds a written specification and TLA+ models of Enclavia's
storage anti-rollback protocol: the customer enclave's `nbd-client` boot
decision and runtime pinning, the replicated synchronizer ("freshness
oracle"), PCR transitions for upgrades, and revocation.

**Which code this models.** The Train 2 synchronizer release: EnclaviaIO/enclavia
branch `train2` at **`f413b5e`** (draft PR #119), including revocation by
upgrade-link hash (`f413b5e`), quorum ACK (`91750ff`), the `valid_from` gate
(`fd09cff`) and the client-write deadline (`f483ce8`). The first revocation
design (`bd673c2`, a per-key `issued_at` watermark, since replaced and no
longer in the branch history) is kept as a negative model. This branch is
based on `master` and contains only `spec/`, so every code citation below is
written as `train2@f413b5e path:line` (short `path:line` in tables means the
same commit) and does not depend on #119 being merged. Facts about the backend
and the deployment cite `enclavia-crates@736c202` (origin/master) and
`deployment@87fb8a9` (origin/master).

Everything here is a model: it checks the protocol logic at small bounds
against an explicit adversary. Section 10 lists what the model takes on trust.

---

## 0. Findings against the design as built

The model was written to find missing edge cases, so this comes first. Each
finding has a TLC counterexample from a configuration that encodes the
current code (`models/Current_*.cfg`); section 7 has the results table and
section 8 the traces.

**Upgrade authorization (self-hosted custody, backend untrusted)**

| # | Finding | Config |
|---|---|---|
| **F8** | **A self-custody owner's revocation can be turned into an upgrade of the backend's choosing (type confusion).** `UpgradePayload` and `RevocationPayload` are plain serde structs without `deny_unknown_fields` (`enclavia-protocol/src/chain.rs:185-212`), decoded with `ciborium::from_reader`, and both are signed raw, with the same control key and no domain tag. Their shared fields (`enclave_id`, `issued_at`, `nonce`) have the same types, so a CBOR map carrying the union of both field sets is a valid `RevocationPayload` **and** a valid `UpgradePayload`. `check_revocation_target` (`enclavia-cli/src/commands/upgrade.rs:505`) decodes the prepared bytes as a revocation and checks exactly the right things about it (the named link is signed by the owner's key, `revokes_link` is its hash, it matches the staged upgrade), so the owner signs. The old enclave verifies it, attests `sha256(payload)` with its own PCRs, commits the (correct) revocation to the synchronizer and hands the link to `chain-host` (`run_revoke_upgrade`, `enclavia-server/src/main.rs:442-512`). The host relabels `ChainLink.kind` (outside every signature) to `Upgrade`: the signature, the `UpgradePayload` decode, the chain attestation (user_data and PCRs = `from_pcrs`; the nonce is not checked for chain links, `enclavia-protocol/src/attestation.rs:683-689`) and a backend-chosen `valid_from` all verify (`verify_transition_link`, `wire.rs:830-899`), and its link hash is not the revoked one. What moves is the pin; the backend-chosen target reads the data only if its KMS key policy allows it, which Enclavia, as the AWS account owner, can arrange, so against a hostile backend the synchronizer is the last barrier. (The byte-level claim rests on serde's default of ignoring unknown map keys; it was argued from the code, not executed. A unit test that decodes one CBOR map as both types would confirm it.) Fix: domain-separate the signatures (sign `tag \|\| payload`) and/or reject unknown fields and require canonical re-encoding, in the CLI, the enclave and the synchronizer. | `Current_PolyglotRevocation` |
| **F7** | **The CLI signs upgrade payloads unchecked.** `confirm_self_hosted` (`enclavia-cli/src/commands/upgrade.rs:342`) calls `sign_confirm_submission` (`enclavia-cli/src/signer.rs:77`), which signs `prep.payload` as received; the only thing printed is `prep.valid_from`, a separate string the backend also supplies and documents as informational (`enclavia-protocol/src/custody.rs:127-129`). f413b5e added checks for revocations only. A hostile backend obtains the owner's signature over an upgrade to **another target** than approved (the only enclave-side use of `to_pcrs` is the optional LUKS re-key, where `enclavia-crypto prepare-upgrade --expected-pcr*` checks that the new KMS key's policy names those PCRs; the backend mints that key, so a hostile backend satisfies the check trivially), or with an **earlier `valid_from`** (checked only by the old enclave's min-upgrade-delay against its guest clock, so that variant needs `min_upgrade_delay_secs = 0` or a guest clock set back by about the delay; the model omits that gate). | `Current_HostileBackend_Target`, `Current_HostileBackend_ValidFrom` |
| F9 | (Fixed by f413b5e; kept as a negative model.) The bd673c2 per-key watermark on `issued_at` was not sound against the backend, which stamps both `UpgradePayload.issued_at` and `RevocationPayload.issued_at` (`enclavia-crates@736c202 enclavia-backend/src/routes/upgrades.rs:842-905`): a back-dated revocation commits and covers nothing, even with a CLI that checks every field. | `Neg_WatermarkHostileBackend` |

f413b5e's revocation itself is sound against a hostile backend: with the CLI
checking revocations only and payload types not separated (the code as it is),
a revocation the owner signs always cancels the link the owner meant
(`Current_HostileBackend_Revocation` passes `RevocationPermanent`); without
`check_revocation_target` it would not (`Neg_RevocationUncheckedCli`). With the
CLI also checking upgrade payloads and strict payload types,
`TransitionAuthorized` holds too (`Fix_Payloads_HostileBackend`). Under
**managed custody** the backend holds the control private key
(`enclavia-crates@736c202 enclavia-backend/src/routes/upgrades.rs:919-920`),
so against Enclavia as the adversary these properties give nothing.

**Freshness oracle and boot decision**

| # | Finding | Needs | Config |
|---|---|---|---|
| **F1a** | **An empty oracle is accepted.** If the host kills all three synchronizer nodes, the restarted nodes form a fresh, empty cluster (`join.rs:197-206` initializes when every peer answers `NoCluster`). A customer enclave booted with a **blank** disk then gets `NotFound`, registers, and serves an empty volume, although the enclave had ACKed writes. The client cannot tell this cluster from the real one: it checks only the synchronizer's PCRs. | host kills 3 nodes (or runs 3 extra nodes from the trusted image) | `Current_HostTotalLoss` |
| **F1b** | **A runtime reconnect can land on a second oracle, and the next Pin silently re-registers there.** On reconnect the client re-dials through the host relay and does not re-run boot verification (`rollback.rs:2139-2159`). The server maps a `Pin` for an unknown key to `Register` and ignores `expected_version` (`raft/serve.rs:240-252`); the client adopts whatever version comes back (`rollback.rs:859`). The host then has two oracles that vouch for different states of the same volume, and restores the older snapshot against the real cluster: **rollback of ACKed writes to real older data**, plus a fork. | a second trusted-image cluster (or a total loss mid-run) | `Current_HostShadow_Stale`, `Current_HostShadow_Fork` |
| **F1c** | **Revocation is only as permanent as the oracle.** After a total loss the revocation state is gone; the still-running old enclave silently re-registers its current state (F1b), and the host replays the revoked link: the revoked successor inherits the **real** data. | total loss | `Current_HostTotalLoss_Revocation` |
| **F1d** | **A client-side version check does not close F1b.** Requiring `PinOk.version = expected + 1` stops the client from adopting a re-registration, but a retried Pin that the server turned into `Register` on the other oracle can commit after the client gave up on it and moved on. That stray registration pins an older state the host restores later. The fix has to be server-side (`ExplicitRegister` below). | as F1b | `Fix_VersionCheck_Shadow_Stale` |
| **F2** | **Successor squatting.** Once an upgrade link A->B is signed (it is public on the chain), the host can boot image B with a blank disk before the transition. B's key is unknown and the disk is blank, so B **registers as a new key** and serves an empty volume under the image the owner designated as A's successor, while A's data is ACKed. Afterwards the legitimate `Transition` A->B is refused forever (`NewKeyAlreadyExists`, `lib.rs:443-445`): that upgrade is blocked. No cluster tricks needed; the documented operational precondition holds. KMS access is bound to PCRs, not to a disk (the host serves the key blob), so the squatting B has the successor's secrets. | booting an image | `Current_Upgrade` |

**Design inputs**

| # | Finding | Config |
|---|---|---|
| F3 | (Confirmed as load-bearing; f413b5e does all three.) The revocation check must sit in the replicated `apply`, be keyed by something **signed and owner-checkable**, and the owner must check what the revocation names before signing. A check only in the leader's pre-check races a concurrently committing `Revoke`; keying by the backend-assigned `ChainLink.id` lets the host relabel the link; keying by `issued_at` lets the backend dodge it (F9); an unchecked CLI lets the backend make the revocation name another link. | `Neg_RevocationAtSubmit`, `Neg_RevocationUnsignedId`, `Neg_RevocationUncheckedCli` |
| F4 | An upgrade link that reached `valid_from` without being executed can never be revoked (the backend refuses once `valid_from` has passed, `enclavia-crates@736c202 enclavia-backend/src/routes/upgrades.rs:1560-1569`) and never expires in the synchronizer (only a lower bound, `wire.rs:866-877`). It stays a bearer credential while the old key is current: the host can execute an upgrade the owner has since abandoned, at any later time. Not model-checked. | |
| F5 | (#122.) All-voter ACK makes a re-seed from a survivor lossless **only if the survivor is a voter of the current configuration**. A node the host partitioned and then replaced through replace-on-rejoin still *believes* it is a voter; a learner still catching up holds a prefix. Re-seeding from either loses ACKed pins, and "am I a current voter" cannot be decided by the survivor alone. | `Opt_AllVoterReseed_Believed`, `_Any` |
| F6 | (What-if.) The pinned value is `SHA-256` of the 4 KiB **superblock** region only. Two forks that write the same amount at the same generation can produce byte-identical superblocks (btrfs stores bytenr/generation pointers, not content hashes). The CAS disambiguation `Get` then accepts the other writer's pin as "our earlier attempt", and both forks get writes ACKed. Needs an experiment on real btrfs. | `WhatIf_SuperblockCollision` |

Root cause shared by F1a-F1d: **the client authenticates the oracle's code
(PCRs), never the oracle's state or identity.** Any cluster running the
trusted image is an acceptable oracle, a freshly initialized one included,
and the client treats "the oracle does not know me" as "first boot" (blank
disk, boot) or as "register me" (runtime Pin). #122's text assumes the
enclave "refuses to mount" when the synchronizer does not know it; that holds
only for a written disk at boot.

Candidate fixes the model checks (none is in the code):

* `ExplicitRegister`: `Register` becomes its own RPC, sent only by the boot
  path and only for a blank disk; `Pin` on an unknown key answers `NotFound`.
  Closes F1b, F1d and the written-data part of F1c
  (`Fix_ExplicitRegister_Shadow_Stale`, `Fix_ExplicitRegister_TotalLoss_RevocationData`).
* `SuccessorMustTransition`: an image built as an upgrade target (the builder
  knows) carries that fact in its measured config and never registers fresh:
  `NotFound` + blank goes to the Transition branch. Closes F2 (`Fix_Upgrade`
  passes every property).
* A CLI that also decodes and checks upgrade payloads (target, `valid_from`)
  plus strict, domain-separated payload types, on top of f413b5e: closes F7
  and F8 (`Fix_Payloads_HostileBackend`).
* F1a (reset to an empty volume) and the blank-volume variant of F1c stay open
  under every fix above (`Fix_VersionCheck_Shadow_Rollback`,
  `Fix_ExplicitRegister_TotalLoss_Revocation`): closing them needs the
  oracle's continuity to be verifiable by the client (#122's cold-start
  design, or the planned customer-driven cluster migration), not just its
  measurements.

Deployment fact behind the dev-synchronizer negative model:
`deployment@87fb8a9 modules/enclavia-backend.nix:149-158` now builds one
synchronizer trust list per mode (production: Nitro cluster only). Storage
images built **before** that split carry the union of the QEMU v2 cluster and
the Nitro cluster (`deployment@794665d modules/enclavia-backend.nix:125-153`)
in their measured config, so for them `Neg_DevSync` is the real situation:
the QEMU synchronizer skips certificate-chain verification of the customer's
attestation (`train2@f413b5e synchronizer/src/main.rs:73-75`, `listener.rs:317`),
so the host can open a session as any key.

Code/documentation mismatches found while mapping:

* `train2@f413b5e nbd-client/src/rollback.rs:27` still says a Pin is ACKed
  "only after the entry is replicated to every voter"; since `91750ff` it is
  a quorum (`raft/mod.rs:106`).
* `train2@f413b5e synchronizer/src/wire.rs:673-674` says enclavia-server
  "applies the same gate on the enclave side before it swaps images". The
  enclave never swaps images: its only `valid_from` check is the
  min-upgrade-delay at `PrepareUpgrade` time against the guest clock
  (`enclavia-server/src/main.rs:283-293`); the backend's cutover sweep swaps.
* `train2@f413b5e synchronizer/src/lib.rs:6-11` calls the pure core a
  translation of `synchronizer-spec/Synchronizer.tla`; that spec (section 11)
  predates CAS pins, `valid_from`, revocation and per-boot identity.
* The f413b5e commit message says that in self custody "the backend cannot
  get a revocation of another link signed in place of the one being revoked".
  True for the revocation itself (`Current_HostileBackend_Revocation`), but
  the same signature can also authorize an upgrade (F8).
* `enclavia-server/src/main.rs:350-353` says a host that warps the guest clock
  *forward* can shrink the min-upgrade-delay; by the inequality at `:290-292`
  (`valid_from < now + delay - 60 s` rejects) it is a *backward* warp that
  admits an earlier `valid_from`.

### Who builds and who signs each payload

| Payload | Built by | Signed by | What the signer checks today |
|---|---|---|---|
| `UpgradePayload{enclave_id, from_pcrs, to_pcrs, image_digest, valid_from, issued_at, nonce}` | backend (`build_upgrade_payload`, `issued_at = row.created_at`) | managed: backend; self-hosted: owner's CLI | nothing: raw bytes signed (F7) |
| `PrepareUpgrade` command envelope `{payload, inner sig, rekey, nonce}` | owner's CLI (`encode_prepare_upgrade`) from backend-supplied pieces | managed: backend; self-hosted: owner's CLI | nothing beyond assembling it |
| Upgrade `ChainLink{kind, payload, attestation, signature}` | old enclave (`run_prepare_upgrade`), after verifying both signatures, the nonce and the min-upgrade-delay (guest clock) | inner signature from above; attestation by the old enclave's NSM | `kind`, `id`, `sequence` are outside every signature |
| `RevocationPayload{enclave_id, revokes, issued_at, nonce, revokes_link}` | backend (`build_revocation_payload`; `revokes_link` = hash of the stored upgrade link's payload, on `enclavia-crates` branch `feat/revocation-link-hash@72bf5b7`, not yet on master) | managed: backend; self-hosted: owner's CLI | `check_revocation_target`: for this enclave, `revokes` is the staged upgrade's chain entry, that entry is an upgrade signed by the owner's key, `revokes_link` is its hash, target and `valid_from` match the staged row and are still pending. Unknown fields are not rejected (F8) |
| Revocation `ChainLink` | old enclave (`run_revoke_upgrade`): attests, commits `Revoke` to the synchronizer, then submits to `chain-host` | as above | as above |
| Customer `Authenticate` document | the enclave's NSM (`nonce = handshake hash`, `user_data = control pubkey` from the measured config) | Nitro | |

---

## 1. Actors and trust assumptions

| Actor | Trusted for | Not trusted for |
|---|---|---|
| Customer enclave (nbd-client, enclavia-server) | its code as measured by PCR0-2; its measured config (`/etc/enclavia/config.json`): control pubkey, synchronizer trust anchors, `debug_attestation` | nothing else: it has no clock of its own and no persistent state outside the disk |
| AWS Nitro hypervisor + NSM | attestation documents are genuine, PCRs reflect the booted image, `timestamp` is hypervisor time, `nonce`/`user_data` are what the enclave asked for | availability |
| AWS root of trust | the Nitro CA chain | |
| Synchronizer node (Nitro, production build) | runs the measured image; verifies full CA chains; reads time from its own NSM | availability, memory persistence (none), identity across restarts (new instance key every boot) |
| Host / operator / relay | nothing | chooses every scheduling, which cluster a vsock dial reaches (`synchronizer-relay`), mesh peer names (`MESH_PEERS` from the unmeasured names-init channel), which disk state and LUKS header to serve, which image to boot and when, which upgrade link `chain-host` returns; can crash/restart nodes, start extra instances of any trusted image, delay/drop/replay any message |
| Disk | nothing: the host can snapshot and restore any sector range, header included | |
| Enclavia (backend) | runs the backend | **may be the adversary**: it is the host operator, and under managed custody it holds the control private key |
| Control-key holder (owner) | signs upgrade and revocation links (P-256) | |
| Dev (QEMU) synchronizer | nothing: the host controls its memory and clock, and its build skips CA-chain checks | |

Cryptographic assumptions: P-256 ECDSA and SHA-256 are unforgeable/collision
resistant; the Noise_NN handshake hash is unique per session, so an
attestation document bound to it (`nonce = handshake_hash`) cannot be replayed
into another session.

## 2. State

Per cluster, the replicated pure core (`train2@f413b5e synchronizer/src/lib.rs`):

* `state: PcrKey -> KeyState{commitment, version, control_pubkey}` for live keys.
* `retired: Set<PcrKey>`: keys moved away by a `Transition` (final).
* per key, the set of revoked upgrade-link hashes (`SHA-256` of the link's
  payload bytes), only ever added to.
* observation sets `attested`, `transition_authorizations` (fed from verified
  replicated entries; they carry no independent authority in Train 2).

`PcrKey = SHA-256(PCR0||PCR1||PCR2)` today (the model treats it abstractly as
"image identity"; a pending change extends it with PCRs 16-31).

Per node: an in-memory log and applied state, a per-boot instance key (its
Raft id), and nothing on disk.

Per customer enclave instance: its `PcrKey`, the disk it is served, the CAS
`expected` version, the `RegionWatch` history of acceptable superblock
commitments.

The commitment is `SHA-256` of the 4 KiB ciphertext at LUKS data offset +
64 KiB (the primary btrfs superblock), `nbd-client/src/rollback.rs:116-122,243`.

## 3. Messages

Customer session (`wire.rs`): Noise_NN handshake; client `Authenticate{nsm_doc}`
(nonce = handshake hash, `user_data` = control pubkey); server `Authenticate`
(its own NSM doc, same nonce); then RPCs, each answered once:

| Request | Server behaviour | Responses |
|---|---|---|
| `Get{key}` | `key` must equal the session key; linearizable read | `GetOk{commitment, version}`, `NotFound`, `Unavailable` |
| `Pin{key, expected_version, commitment}` | `key` = session key; if the key is unknown **locally** -> `Register{key, commitment, control_pubkey}` (expected_version ignored), else CAS `Pin`; `AlreadyRegistered` -> one retry as `Pin` | `PinOk{version}`, `VersionConflict`, `NotFound`, `OperationRejected`, `Unavailable` |
| `Transition{link}` | derive `old/new` from the signed payload; `new` = session key; P-256 signature under `old`'s frozen pubkey; chain attestation of the old enclave; NSM `now >= valid_from - 60 s`; replicated apply re-checks liveness and whether the link hash was revoked | `TransitionOk{version}`, `TransitionRejected`, `TransitionRevoked` |
| `Revoke{link}` | session key registered; signature under its frozen pubkey; apply adds `revokes_link` to the key's revoked set | `RevokeOk`, `RevocationRejected` |

Mesh (node-node): Noise + mutual attestation against the self-PCR allowlist +
identity-key signature; Raft RPCs and `Join`.

## 4. Boot state machine (nbd-client)

`boot` (`rollback.rs:2104`): connect and mutually authenticate, check the LUKS2
data offset, read the superblock region `r`, `Get(key)`:

| Oracle answer | Region | Decision |
|---|---|---|
| `Found{c, v}`, `hash(r) = c` | any | **Serve** with `expected = v` |
| `Found{c, v}`, `hash(r) != c` | any | FailStop |
| `NotFound` | blank (all zero) | **RegisterThenServe**: `Pin(expected 0, hash(r))`, must answer `version 0` (a `VersionConflict` is disambiguated with `Get`) |
| `NotFound` | written | **TransitionOrFailStop**: fetch the latest upgrade link from `chain-host` (host-controlled), `Transition{link}`, then `Get` again and require `Found` with a matching hash |
| error / timeout | | FailStop |

Runtime: every write covering the region is hashed, `Pin(key, expected, h)`
is sent, and the NBD reply is held until `PinOk`; `expected := version`
(`rollback.rs:859`). `VersionConflict` -> `Get`: our commitment means our
earlier attempt landed, anything else is fatal. Dropped sessions are
re-established up to 3 times (fresh dial, fresh mutual attestation, **no
boot re-verification**, `rollback.rs:2140-2145`); `Unavailable` is retried
for up to 300 s. Every region-covering read is checked against the pinned
history (`RegionWatch`).

## 5. Upgrade and revocation

1. The owner confirms an upgrade. The backend builds the
   `UpgradePayload{enclave_id, from_pcrs, to_pcrs, image_digest, valid_from,
   issued_at, nonce}`; the backend (managed custody) or the owner's CLI
   (self-hosted) signs it, together with a `PrepareUpgrade` envelope over the
   enclave's current control nonce.
2. The old enclave checks the min-upgrade-delay against its own clock,
   optionally re-keys LUKS for the new PCRs, and emits the upgrade
   `ChainLink{signature, attestation(user_data = sha256(payload))}` to
   `chain-host` (`enclavia-server/src/main.rs:312`).
3. After `valid_from` the backend's cutover sweep stops the old instance and
   boots the new image. The new enclave's boot finds `NotFound` + written
   disk and submits `Transition{link}`; the synchronizer moves the pin from
   `old` to `new` (commitment and version carried), retires `old`, and
   freezes `new`'s control pubkey.
4. Revocation (before `valid_from`, enforced only by the backend): the old
   enclave commits `Revoke{revocation link}` to the synchronizer over its own
   session **before** reporting success (`enclavia-server/src/sync_revoke.rs`);
   the committed `Revoke` adds `revokes_link` (the hash of the cancelled
   upgrade payload) to the key's revoked set, and the replicated apply refuses
   a Transition whose link hash is in that set (`lib.rs:440-441, 466-477`).
   Revocation is refused once the pin has moved. In self custody the CLI
   signs a revocation only after `check_revocation_target`
   (`enclavia-cli/src/commands/upgrade.rs:505`). The first design (bd673c2)
   compared the links' backend-stamped `issued_at` with a per-key watermark
   instead (F9); the model's `RevocationMode` covers both.

## 6. Cluster durability model

Three member slots; a node's Raft id is its per-boot instance key. A write is
ACKed when openraft commits it: on a quorum (2 of 3) of the voter set and
applied on the leader (`raft/mod.rs:106-139`, `691`). A crashed node loses
everything; a restarted node is a new identity that must be admitted by the
leader (`add_learner` catch-up, then `change_membership` replacing the slot's
previous holder, `raft/mod.rs:839-923`). Losing two nodes halts writes and
reads. Losing all three and restarting yields a fresh cluster
(`join.rs:197-206`). No re-seed path exists; #122 plans one together with a
return to all-voter ACK.

---

## 7. Properties and results

Properties (all in `AntiRollback.tla`, section PROPERTIES). A *lineage* is the
set of images connected by signed upgrade links at the moment of the check.

| Property | Precise statement |
|---|---|
| `NoRollback` | Whenever an instance **begins serving** (Serve, RegisterThenServe, post-Transition Get), its disk state extends every state already ACKed in its lineage. Evaluated at the operation's linearization point: a live instance's view may lag behind a later ACK by another instance (by design; the CAS catches a clone at its next pin). |
| `NoStaleRestore` | Narrower: an instance never begins serving a **written** state that is a strict ancestor (older version) of a state already ACKed in its lineage. |
| `NoFork` | The ACKed states of a lineage form a single chain (no two instances ever get divergent writes acknowledged). |
| `TransitionAuthorized` | A `Transition` from A to B applies only if the owner **approved** an upgrade A->B (confirmed that template; a signature the backend obtained over other bytes does not count), the leader's NSM time at submission was `>= valid_from - Tol` for the valid_from the owner approved, and no revocation the owner **meant** for that link was committed earlier in the same cluster history. |
| `RevocationPermanent` | Once a revocation the owner meant for link L is committed in any cluster (whatever the backend put in its payload), L never moves a pin afterwards, in any cluster history. `RevocationPermanentData`: weaker, L never moves a pin whose data derives from a written state the lineage had ACKed when the revocation committed (the owner's real data, as opposed to a fresh volume). |
| `OwnerOnly` | Only a session attested as key K registers or pins under K. |
| `AckDurability` | Every write ACKed by the real cluster stays committed at the same log position (survives any node loss short of re-initialization). |
| `LeaderCompleteness` | Sanity check of the Raft abstraction: the leader's log covers the commit index. |

Results (TLC 2.19, `-deadlock`, beta, see `runs/`):

<!-- RESULTS-BEGIN -->
| Config | Expected | Observed | Result | Wall clock (TLC workers) |
|---|---|---|---|---|
| `Current_Cluster` | pass | pass | 5,007,205 distinct states, depth 36 | 01min 22s (4) |
| `Current_HostileBackend_Revocation` | pass | pass | 802,210,331 distinct states, depth 34 | 01h 15min (24) |
| `Current_HostileBackend_Target` | violation TransitionAuthorized | violation TransitionAuthorized | counterexample, 15 states | 07s (4) |
| `Current_HostileBackend_ValidFrom` | violation TransitionAuthorized | violation TransitionAuthorized | counterexample, 14 states | 07s (4) |
| `Current_HostShadow_Fork` | violation NoFork | violation NoFork | counterexample, 16 states | 07s (4) |
| `Current_HostShadow_Stale` | violation NoStaleRestore | violation NoStaleRestore | counterexample, 16 states | 12s (4) |
| `Current_HostTotalLoss` | violation NoRollback | violation NoRollback | counterexample, 18 states | 09s (4) |
| `Current_HostTotalLoss_Revocation` | violation RevocationPermanentData | violation RevocationPermanentData | counterexample, 28 states | 25min 48s (4) |
| `Current_HostTotalLoss_Stale` | pass | pass | 45,747,078 distinct states, depth 39 | 24min 37s (4) |
| `Current_PolyglotRevocation` | violation TransitionAuthorized | violation TransitionAuthorized | counterexample, 16 states | 17s (4) |
| `Current_UpgradeAuth` | pass | pass | 41,847,648 distinct states, depth 37 | 18min 40s (4) |
| `Current_Upgrade` | violation NoRollback | violation NoRollback | counterexample, 20 states | 16s (4) |
| `Fix_ExplicitRegister_Shadow_Stale` | pass | pass | 122,581,074 distinct states, depth 38 | 53min 25s (4) |
| `Fix_ExplicitRegister_TotalLoss_Revocation` | violation RevocationPermanent | violation RevocationPermanent | counterexample, 23 states | 29min 01s (4) |
| `Fix_ExplicitRegister_TotalLoss_RevocationData` | pass | pass | 30,655,327 distinct states, depth 38 | 16min 12s (4) |
| `Fix_Payloads_HostileBackend` | pass | pass | 119,523,648 distinct states, depth 34 | 47min 49s (4) |
| `Fix_Upgrade` | pass | pass | 116,628,713 distinct states, depth 37 | 48min 56s (4) |
| `Fix_VersionCheck_Shadow_Rollback` | violation NoRollback | violation NoRollback | counterexample, 14 states | 02s (4) |
| `Fix_VersionCheck_Shadow_Stale` | violation NoStaleRestore | violation NoStaleRestore | counterexample, 18 states | 33s (4) |
| `Neg_DevSync` | violation NoRollback | violation NoRollback | counterexample, 10 states | 01s (4) |
| `Neg_DevSync_Owner` | violation OwnerOnly | violation OwnerOnly | counterexample, 2 states | 00s (4) |
| `Neg_NoRevocation` | violation RevocationPermanent | violation RevocationPermanent | counterexample, 19 states | 10s (4) |
| `Neg_NoValidFrom` | violation TransitionAuthorized | violation TransitionAuthorized | counterexample, 14 states | 03s (4) |
| `Neg_QuorumReseed` | violation AckDurability | violation AckDurability | counterexample, 10 states | 01s (4) |
| `Neg_QuorumReseed_Stale` | violation NoStaleRestore | violation NoStaleRestore | counterexample, 23 states | 34s (4) |
| `Neg_RevocationAtSubmit` | violation RevocationPermanent | violation RevocationPermanent | counterexample, 19 states | 14s (4) |
| `Neg_RevocationUncheckedCli` | violation RevocationPermanent | violation RevocationPermanent | counterexample, 18 states | 02min 36s (4) |
| `Neg_RevocationUnsignedId` | violation RevocationPermanent | violation RevocationPermanent | counterexample, 19 states | 14s (4) |
| `Neg_WatermarkHostileBackend` | violation RevocationPermanent | violation RevocationPermanent | counterexample, 19 states | 42s (4) |
| `Opt_AllVoterReseed_Any` | violation AckDurability | violation AckDurability | counterexample, 12 states | 01s (4) |
| `Opt_AllVoterReseed_Believed` | violation AckDurability | violation AckDurability | counterexample, 12 states | 01s (4) |
| `Opt_AllVoterReseed_Current` | pass | pass | 3,690,879 distinct states, depth 37 | 54s (4) |
| `WhatIf_SuperblockCollision` | violation NoFork | violation NoFork | counterexample, 20 states | 07s (4) |

All 33 configurations match their `EXPECT` line. Wall clock is on the beta builder (48 cores, shared), with the TLC worker count in parentheses.
<!-- RESULTS-END -->

---

## 8. Counterexamples

Traces are summarized from the TLC output in `runs/` (full states there).
"E1, E2" are customer enclave instances; `R` is the real cluster, `S` the
host-run second cluster; disk state 0 is blank, 1 and 2 are successive writes.

**Findings against the design as built**

* `Current_Upgrade` (F2): the owner signs A->B. E1 boots A on a blank disk,
  registers, writes state 1 (ACKed). E2 boots **B** on a blank disk: `Get(B)`
  is `NotFound`, the disk is blank, so E2 registers B and serves the empty
  volume while A's state 1 is ACKed. `NoRollback` fails.
* `Current_HostileBackend_Target` (F7): the owner approves A->B; the backend
  hands the CLI a payload for A->C, which it signs. E1 runs A with state 1;
  E2 boots C with that disk, gets `NotFound`, submits the signed A->C link; the
  synchronizer accepts it. `TransitionAuthorized` fails.
* `Current_HostileBackend_ValidFrom` (F7): same, the signed `valid_from` is
  0 instead of the approved 2; the Transition commits at time 0.
* `Neg_WatermarkHostileBackend` (F9, the superseded bd673c2 watermark, CLI that
  checks every field): link `issued_at = 1`, the backend stamps the revocation
  `issued_at = 0`. A commits the revocation (watermark 0), B submits the link
  (1 > 0): the pin moves. `RevocationPermanent` fails.
* `Current_PolyglotRevocation` (F8, f413b5e with the CLI checking everything
  it signs): the revocation of A->B the owner signs is also an upgrade
  payload with an earlier `valid_from`; B transitions with it, and its hash
  is not the revoked link hash. `TransitionAuthorized` fails.
* `Current_HostTotalLoss` (F1a): E1 registers A on a blank disk, writes state
  1 (ACKed). The host kills all three nodes; the restarted nodes form an empty
  cluster. E2 on a blank disk gets `NotFound`, registers and serves blank.
  `NoRollback` fails.
* `Current_HostShadow_Stale` (F1b): E1 registers on `S`, writes 1 (ACKed on
  `S`), writes 2; the host drops the session and the reconnect reaches `R`,
  where the key is unknown: the Pin becomes `Register(2)`, answered
  `PinOk(0)`, and E1 accepts it (2 ACKed). E2 boots with the disk snapshot at
  state 1 against `S`, which still says 1: served. `NoStaleRestore` fails.
* `Current_HostShadow_Fork` (F1b): two instances get divergent states ACKed on
  the two clusters. `NoFork` fails.
* `Current_HostTotalLoss_Revocation` (F1c): E1 runs A, writes 1 (ACKed), the
  owner revokes A->B and E1 commits it. The host kills all three nodes. E1's
  next Pin (state 2) re-registers A on the fresh cluster. E2 boots B (with `SuccessorMustTransition` even a blank disk goes to the
  Transition branch) and submits the revoked link: the fresh cluster has no revocation state,
  the pin (data derived from state 1) moves to B. `RevocationPermanentData`
  fails.

**Candidate fixes**

* `Fix_VersionCheck_Shadow_Stale` (F1d): with the client-side version check,
  E1 writes 1 on `S`, the host reconnects it to `R`, its Pin is appended as
  `Register(1)` there; the host drops the session before the answer, E1
  reconnects to `S`, pins 1 and 2 there (ACKed). The stray `Register(1)`
  commits on `R`; E2 boots with state 1 against `R` and serves.
  `NoStaleRestore` fails.
* `Fix_VersionCheck_Shadow_Rollback`: the blank-disk registration of F1a still
  goes through on `S`. `NoRollback` fails.
* `Fix_ExplicitRegister_TotalLoss_Revocation`: after the total loss the host
  boots A on a blank disk (registers), then B with the revoked link: the pin
  moves (blank volume only). `RevocationPermanent` fails;
  `RevocationPermanentData` holds.

**Required negative models (regression evidence)**

* `Neg_DevSync`: the host opens a session on the dev synchronizer as A and
  registers the blank state; E1 boots, writes state 1 (ACKed); the host pins
  the blank commitment again under A; E2 boots a blank disk and it is served. `NoRollback` fails.
* `Neg_DevSync_Owner`: the host pins under A on the dev synchronizer.
  `OwnerOnly` fails (3 steps).
* `Neg_QuorumReseed`: a registration commits on the leader and one follower
  (quorum) and is ACKed; the third node lags. The host kills the two holders;
  the operator re-seeds from the lagging voter: the ACKed entry is gone.
  `AckDurability` fails.
* `Neg_QuorumReseed_Stale`: E1 pins states 1 and 2; state 2 is committed on
  the leader and a freshly admitted node (quorum) and ACKed. Both die; the
  operator re-seeds from the remaining voter, which holds state 1; E2 boots
  the state-1 snapshot and it is served. `NoStaleRestore` fails.
* `Neg_NoValidFrom`: B transitions at time 0 with a link whose `valid_from`
  is 2. `TransitionAuthorized` fails.
* `Neg_NoRevocation`: A commits the revocation, B transitions with the revoked
  link anyway. `RevocationPermanent` fails.
* `Neg_RevocationAtSubmit`: B's Transition passes the leader's pre-check while
  A's Revoke is appended but not yet applied; both commit, Revoke first, and
  the Transition is not re-checked. `RevocationPermanent` fails.
* `Neg_RevocationUnsignedId`: the revocation records the backend id 1; the
  host presents the same signed link labeled id 2. `RevocationPermanent`
  fails.
* `Neg_RevocationUncheckedCli`: without `check_revocation_target` the backend
  builds a revocation whose `revokes_link` names no signed link; the owner
  signs it, A commits it, and B still transitions with the link the owner
  meant to revoke. `RevocationPermanent` fails.
* `Opt_AllVoterReseed_Believed` (F5): the host partitions node 3, starts
  node 4 for slot 3 and the leader admits it (node 3 evicted, but still
  believes it is a voter). A registration is ACKed on all of `{1, 2, 4}`.
  Nodes 1 and 2 die; the operator re-seeds from node 3, which never received
  the entry. `AckDurability` fails.
* `Opt_AllVoterReseed_Any`: same with a learner as the source.
* `WhatIf_SuperblockCollision` (F6): two instances booted from the same state
  write different data with identical superblocks; the loser's CAS conflict is
  resolved by the `Get` as "our own earlier pin". `NoFork` fails.

---

## 9. The model

`AntiRollback.tla` (one module, switches as constants) and
`MCAntiRollback.tla` (concrete values). Structure:

* **Real cluster `R`**: up to `MaxInst` node instances in 3 slots; each holds
  a prefix of the leader's log (`has`); the voter set `cfg`; commit when a
  majority of `cfg` holds an entry; crash wipes a node; `Start` creates a new
  instance for a slot (also while the holder is alive: a clone);
  `Admit` = catch up + replace the slot's holder; `Elect` after the leader
  dies picks the up voter with the longest log and truncates the uncommitted
  tail. `AckPolicy` = quorum (ACK at commit) or all (ACK when every voter in
  `cfg` holds the entry).
* **Host-run clusters**: `S` (same trusted image, host-operated) and `D`
  (dev, skip-chain) are atomic stores; on `D` the host can pin as any key.
* **Pure core**: `ApplyE` mirrors `StateMachine::apply` for Register, Pin (CAS),
  Transition (liveness, retirement, revoked links) and Revoke.
* **Customer instances**: boot decision table, registration (with the
  `AlreadyRegistered` retry), Transition with any signed link the host picks
  (and any unsigned id label), post-Transition Get, runtime writes and pins
  with at-least-once retries, reconnect to any cluster, `VersionConflict`
  disambiguation, revocation submission by the old enclave.
* **Owner, backend and time**: the owner approves upgrade templates and
  revokes links before `valid_from`. The **backend builds every payload the
  owner signs**: with `HostileBackend` it picks `issued_at` freely, and with
  `CliChecks = "none"` (today) also the target and `valid_from`, and what a
  revocation names; with `StrictPayloads = FALSE` a revocation it builds is
  also a usable upgrade link out of the same key (F8). Signed links are
  public; the host replays any of them. NSM time ticks and cannot be moved by
  the host.
* **Disk**: states `0..MaxState` with a parent function; 0 is blank; the host
  can serve any state ever written.
* **Switches**: `AckPolicy`, `AllowTotalLoss`, `Shadow`, `DevTrusted`,
  `ValidFromGate`, `RevocationMode` (`linkhash` = f413b5e, `watermark` =
  bd673c2, `none`, `submit`, `unsigned_id`), `CliChecks` (`none`, `revocation` =
  f413b5e, `decode`), `HostileBackend`,
  `StrictPayloads`, `Reseed` (`none`, `current`, `believed`, `any`),
  `CommitMode` (`injective`, `shape`), and the candidate fixes
  `ClientVersionCheck`, `ExplicitRegister`, `SuccessorMustTransition`.

Bounds used (per config in `models/`): 1-3 images, one upgrade template A->B
(valid_from 2, issued_at 1, Tol 1; a hostile backend may also stamp
issued_at 0 or 2 and valid_from 0), 1-2 disk writes, 2-3 enclave instances,
3-4 node instances, log length 4, 4-5 submissions, time 0..2, at most one
total loss or re-seed.

### Mapping: spec action -> code (`train2@f413b5e` unless stated)

| Spec action / definition | Code (`train2@f413b5e` unless stated) |
|---|---|
| `ApplyE` Reg | `synchronizer/src/lib.rs:383` `apply_register` |
| `ApplyE` Pin (CAS) | `lib.rs:407-420` `apply_pin` (`expected_version` check at 417) |
| `ApplyE` Trans | `lib.rs:428-464` `apply_transition` (revoked-link check at 440-441, `NewKeyAlreadyExists` at 443-445) |
| `ApplyE` Rev, `RevokedAtApply` (`linkhash`) | `lib.rs:466-477` `apply_revoke`, `lib.rs:481` `is_revoked` (`revoked_links`, `lib.rs:322`); `watermark` is bd673c2 (not in the branch history) |
| replicated entries, follower replay | `raft/mod.rs:188-246` `ReplicatedOp`; `raft/store.rs:276-322` |
| `Submit` to R, `AdvanceR`, quorum ACK | `raft/mod.rs:691` `client_write` (ACK = openraft commit); `raft/mod.rs:106-139` |
| `AckReady` with `AckPolicy = "all"` | pre-Train 2 `client_write_durable`, replaced by `91750ff` |
| `Avail` (linearizable read) | `raft/mod.rs:782` `linearizable_get`; `raft/serve.rs:168-184` `handle_get` |
| `BootRegister`, `PinSubmit` (Pin -> Register mapping) | `raft/serve.rs:213-302` `handle_pin` (local hint at 240, `Register` at 249) |
| `RegRetryAsPin` | `raft/serve.rs:275-290` |
| `BootTransition`, `TransOk` | `raft/serve.rs:331-420` `handle_transition`; `wire.rs:830-899` `verify_transition_link` (session key 841, signature 854-860, `valid_from` 866-877, chain attestation after) |
| NSM time `now` | `trusted_time.rs:27` `now_ms`; `serve.rs:355` |
| `Tol` | `wire.rs:678` `TRANSITION_VALID_FROM_TOLERANCE_MS = 60_000` |
| `SubmitRevoke` | `enclavia-server/src/main.rs:442-512` `run_revoke_upgrade`; `enclavia-server/src/sync_revoke.rs:64` `commit_revocation`; `raft/serve.rs:128-162` `handle_revoke`; `wire.rs:978-1002` `verify_revocation_link` |
| `Issue` (backend builds, owner signs) | `enclavia-crates@736c202 enclavia-backend/src/routes/upgrades.rs:842` `build_upgrade_payload`; `enclavia-cli/src/commands/upgrade.rs:342` `confirm_self_hosted` -> `enclavia-cli/src/signer.rs:77-85` `sign_confirm_submission` (no check); `enclavia-server/src/main.rs:312` `run_prepare_upgrade` |
| `IssueRevoke` | `enclavia-crates@736c202 .../upgrades.rs:895` `build_revocation_payload` (with `revokes_link`: branch `feat/revocation-link-hash@72bf5b7`, `upgrades.rs:901-924`, hash computed at `:1595`), `:1560-1569` pre-activation check; `enclavia-cli/src/commands/upgrade.rs:388` `revoke_self_hosted`, `:505` `check_revocation_target`; `enclavia-cli/src/signer.rs:89-97` `sign_revoke_submission` |
| `StrictPayloads = FALSE` | `enclavia-protocol/src/chain.rs:185-212` (no `deny_unknown_fields`); decoded at `enclavia-server/src/main.rs:334`, `wire.rs:997`, `enclavia-cli/src/commands/upgrade.rs:520` |
| session binding, `OwnerOnly` | `listener.rs:317-334` (key = verified PCR digest); `raft/serve.rs:169,221` (`key == session_key`) |
| `Boot`, `BootGet` decision table | `nbd-client/src/rollback.rs:2104` `boot`; `:307-333` `boot_decision`; `:1539-1618` `verify_or_register` |
| `Get2` (post-Transition re-verify) | `rollback.rs:1642-1719` `transition_and_reverify` |
| link choice by the host | `rollback.rs:1341` `fetch_latest_upgrade_link` (chain-host, host-side) |
| `Write` + `Deliver` (pin gate) | `rollback.rs:958` `pin_with_retries`; `:842-873` `pin_once_on` (`*expected = version` at 859) |
| `Disambiguate` | `rollback.rs:1489-1525` `disambiguate_conflict` |
| `Reconnect` (no boot re-verification) | `rollback.rs:2139-2159` `into_pinner`; `:2040` `connect_and_authenticate` |
| server PCR check (trust anchors) | `wire.rs:580` `verify_server_attestation`; `rollback.rs:1961` `load_synchronizer_trust` |
| `Crash`, `Start` (new identity) | `raft/membership.rs:71` `instance_node_id` (per-boot key) |
| `Admit` | `raft/mod.rs:839-923` `admit` (`add_learner` 880, `change_membership` 910); `raft/membership.rs:207` `plan_admission` |
| `LearnEviction` | `raft/join.rs:371-402` `watch_for_eviction` |
| `Elect` | openraft (assumed, section 10) |
| `TotalReset` (fresh cluster) | `raft/join.rs:124-209` `discover_and_join`, `:223` `try_initialize_fresh`, `:283` 3-member minimum |
| `ReseedFrom` | not implemented (#122 plan) |
| `AdvPinD` (dev synchronizer) | `synchronizer/src/main.rs:73-75` `DEBUG_MODE`; `listener.rs:317` (`VerificationMode::from_debug_flag`) |
| `Com` | `rollback.rs:116-122, 243` (SHA-256 of the 4 KiB primary superblock ciphertext) |

---

## 10. Assumptions we rely on but do not model

* **Raft (openraft)**: log matching; leader completeness for committed entries,
  including across joint-consensus membership changes; a deposed or evicted
  leader cannot commit or serve a linearizable read. The model only elects on
  leader death and picks the longest log; `LeaderCompleteness` checks that
  abstraction, not openraft.
* **Crypto**: P-256 signatures, SHA-256, Noise_NN channel binding, AEAD.
* **NSM honesty**: PCRs, `nonce`, `user_data` and `timestamp` in genuine
  documents are what the hypervisor saw; the Nitro CA chain validation
  (at the document's own timestamp, 24 h skew bound for session documents,
  `enclavia-protocol/src/attestation.rs:729,775-799`) is correct.
* **Session binding**: a session's key is the verified PCR digest
  (`listener.rs:317-334`) and every RPC re-checks `key == session_key`
  (`raft/serve.rs:169,221`). The model has no forged sessions except on `D`.
* **Commitment soundness**: the superblock hash identifies the filesystem
  state (`CommitMode = injective`); F6 shows what breaks if it does not. The
  LUKS header is **not** covered by the pin; restoring an old header (for
  example one with a killed keyslot) is outside the model.
* **RegionWatch** runtime read verification and the LUKS data-offset check are
  not modeled; the model's "serve" is the boot decision.
* **Liveness**: not checked (safety only). Censorship of a revocation by the
  host is always possible and only makes the owner's revoke command fail.
* **Defence in depth around revocation** is not modeled: `run_revoke_upgrade`
  can kill the new LUKS keyslot (`rollback` flag), and the backend schedules
  deletion of the successor's KMS key. Against a hostile host with an honest
  backend the KMS deletion is an independent barrier for F1c (the revoked
  successor cannot decrypt the volume once the key is disabled); the keyslot
  kill is not (the host restores the old LUKS header, which the pin does not
  cover). Against a hostile backend (F7-F9) neither helps.

### Limits of the bounded check

* Bounds: one lineage, at most three images and one upgrade template, one or
  two disk writes, two or three enclave instances, three or four node
  instances, log length 4, four or five submissions, time 0..2, at most one
  total loss or re-seed. A pass is exhaustive only
  within these bounds.
* Time is discrete; `Tol` is one tick. Clock skew between nodes is not
  modeled (all nodes read the same NSM time).
* The serve check is evaluated at the operation's linearization point. A live
  instance keeps serving what it had until its next pin (stale reads between
  pins are accepted by the design and not flagged).
* Payloads are records, not bytes: the polyglot attack (F8) is modeled as
  "a revocation the backend builds is also a usable upgrade link", and the
  attestation the old enclave adds is assumed to be available to the host.
* The optional customer-driven cluster-migration module was not written. F1
  is its central requirement: a trust list of cluster *measurements* (even
  role-tagged current/predecessor) does not tell the client which cluster
  *instance* holds its state.

## 11. The May 2026 spec (`may-2026/`)

Origin: a local repository `synchronizer-spec` (no remote), commits
`d706e49` (2026-05-08, initial spec), `a1e1375` (2026-05-09, MCBig +
MCDiverse), `1459306` (2026-05-12, MCDiverse run at MaxOps=5). Imported
verbatim (history not imported); its captured runs are in `may-2026/runs/`.
It still passes: re-run of `MCSynchronizer` on TLC 2.19 found 517,150 distinct states at depth 30, the same as the May capture (`runs/May_MCSynchronizer.log`).

It models the pure core over an abstract committed log. What changed and why:

| May spec | Current code | Consequence |
|---|---|---|
| Control-key signatures are Ed25519 (`Synchronizer.tla:18`) | ECDSA P-256, raw r\|\|s (`lib.rs:22-33`, `wire.rs:854-860`) | comment only |
| `Pin` has no CAS | `Pin{expected_version}` (`lib.rs:407-420`) | new: fork detection is modeled |
| `AdversaryPropose(Pin)` commits with only `KeyIsCurrent`; no invariant ties a Pin to its owner | session binding in the server (`serve.rs:221`) | the header's "never returns a commitment not pinned by the legitimate owner" had no invariant; now `OwnerOnly` |
| `SignTransition` requires the old key current and the new key attested; signatures bind `(old, new)` only | link payload binds PCRs, `valid_from`, `issued_at`; verified at submission with NSM time | `valid_from` gate and revocation added |
| no revocation | revoked link hashes checked in apply (`lib.rs:440,466`) | new |
| `NodeFail` forbids losing a second node; `NodeRecover` keeps the node's identity and index | per-boot identity, leader admission, 2 losses halt, 3 losses re-initialize | new cluster model |
| single global committed log, commit on any 2 up nodes | quorum of the voter set, ACK at commit (`91750ff`) | ACK policy and re-seed modeled |
| no client | nbd-client boot decision and runtime | new: the end-to-end properties |
| `MCDiverse.tla` comment says MaxOps=7, value is 5 | | cosmetic |

## 12. Running

```
spec/check.sh                 # every model under models/, asserts EXPECT lines
spec/check.sh 'Neg_*'         # a subset
spec/check.sh --may           # also the May core spec
JOBS=8 WORKERS=6 spec/check.sh
HEAVY=1 spec/check.sh          # also the exhaustive positive models
```

Each `models/*.cfg` starts with an `\* EXPECT:` line (`pass` or
`violation <Invariant>`); `check.sh` fails if TLC disagrees. It uses `tlc` from
`PATH` or `nix shell nixpkgs#tlaplus`. The default set (every counterexample
and the smaller positive models) runs in a few minutes and is meant for CI;
models marked `\* TIER: heavy` explore 30-800 million distinct states and take from
tens of minutes to hours each (see the wall-clock column in section 7).
TLC output of the recorded runs is in `runs/` (progress lines stripped).
