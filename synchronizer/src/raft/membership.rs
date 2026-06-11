//! Clone-resistant Raft membership: per-boot instance keys as member
//! identity (EnclaviaIO/enclavia-crates#209).
//!
//! ## Threat
//!
//! Attestation proves WHAT is running, never WHICH instance. All three
//! synchronizer nodes run the same measured image, so a malicious host can
//! boot a second copy of it (a clone) and point routing at it. If Raft
//! member identity derives from anything the host can replay (the logical
//! name, the PCR digest), two honest processes can hold the same voting
//! identity at once, and a duplicated voter lets the host engineer two
//! leaders in one term: split-brain, committed-view regression, rollback,
//! exactly the oracle's threat model.
//!
//! ## Identity
//!
//! Member identity is therefore the node's per-boot P-256 mesh instance
//! key: generated inside the enclave at startup, never serialized out (see
//! [`MeshIdentity`](crate::mesh::identity::MeshIdentity)), and proven live
//! on every mesh connection by signing the Noise handshake hash. A clone
//! cannot impersonate an existing member because it cannot sign with that
//! member's key; the worst it can do is request a REPLACEMENT through the
//! same path a genuine restart uses, which degrades to membership churn
//! (DoS the host can already inflict by dropping packets), never to two
//! simultaneous holders of one vote.
//!
//! Logical names remain pure ROUTING labels (what `mesh-host` resolves);
//! they carry no authority. The configured name set only bounds the
//! cluster's shape: one member slot per configured name.
//!
//! ## The kernel and its caller contract
//!
//! This module is the decision kernel: pure functions from committed
//! membership + an admission request to an [`AdmissionPlan`]. It performs
//! no I/O and no crypto. The SECURITY of the scheme therefore rests on one
//! caller obligation, stated here once and repeated on every entry point:
//!
//! > `candidate_pubkey` MUST be the instance pubkey extracted from the
//! > candidate's mutually-attested mesh channel
//! > ([`PeerIdentity::mesh_pubkey`](crate::mesh::handshake::PeerIdentity)),
//! > never a value read out of a request payload. The channel attestation
//! > is what binds the key to a live same-image enclave; a payload field
//! > would be host-forgeable.
//!
//! The plan is then executed leader-side as `add_learner` followed by one
//! atomic `change_membership` (joint consensus), both linearized through
//! the Raft log, which is what upholds the invariant below.
//!
//! ## Invariant: one instance per slot
//!
//! In every committed membership, each configured name holds at most one
//! voter, and every voter's id equals [`instance_node_id`] of its recorded
//! pubkey. [`AdmissionPlan`] preserves it by construction: admitting a
//! candidate for a slot evicts the slot's previous holder in the same
//! membership change.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::CONTROL_PUBKEY_LEN;
use crate::raft::RaftNodeId;

/// Derive a member's [`RaftNodeId`] from its per-boot instance pubkey: the
/// first 8 bytes (big-endian) of `SHA-256(pubkey)`. Deterministic, so every
/// node derives the identical id for a peer it met over the mesh; collision
/// probability across a 3-node cluster's lifetime of restarts is negligible
/// (and a collision is detected: [`plan_admission`] rejects a candidate
/// whose id equals a DIFFERENT slot's live voter).
pub fn instance_node_id(pubkey: &[u8; CONTROL_PUBKEY_LEN]) -> RaftNodeId {
    let digest = Sha256::digest(pubkey);
    u64::from_be_bytes(digest[..8].try_into().expect("sha256 output >= 8 bytes"))
}

/// One member as recorded in the replicated membership: its routing name
/// plus the instance pubkey its [`RaftNodeId`] derives from. This is the
/// openraft `Node` payload for the cluster (the wiring layer implements
/// `openraft::Node` for it), so every replica can re-derive and re-check
/// ids and slots from committed state alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRecord {
    /// Routing label (what `mesh-host` resolves); one of the configured
    /// names. Carries no authority.
    pub name: String,
    /// 65-byte SEC1 P-256 per-boot instance pubkey. The member's
    /// [`RaftNodeId`] is [`instance_node_id`] of this value.
    pub pubkey: [u8; CONTROL_PUBKEY_LEN],
}

/// Why an admission request was refused. Every variant is a deterministic
/// function of committed state + the request, so leaders at the same log
/// index decide identically.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionError {
    /// The requested slot name is not in the configured cluster shape.
    #[error("name {0:?} is not a configured member slot")]
    UnknownSlot(String),
    /// The candidate's derived id collides with a live voter holding a
    /// DIFFERENT slot. Astronomically unlikely (truncated SHA-256), but
    /// admitting it would conflate two members, so it is refused.
    #[error("candidate id collides with live member of slot {0:?}")]
    IdCollision(String),
    /// A committed membership violates the one-instance-per-slot invariant
    /// (two voters share `name`). This indicates a bug in the wiring layer,
    /// not a property of the request; refuse rather than guess.
    #[error("committed membership holds {0} voters for slot {1:?}")]
    CorruptMembership(usize, String),
    /// A committed voter's id does not equal [`instance_node_id`] of its
    /// recorded pubkey. Same class as [`AdmissionError::CorruptMembership`].
    #[error("committed voter {0} id does not match its recorded pubkey")]
    IdMismatch(RaftNodeId),
}

/// The leader-side outcome of a valid admission request: which node to add,
/// which (if any) to evict, and the exact voter set to commit. Executed as
/// `add_learner(added_id, added)` then one `change_membership(new_voter_ids)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionPlan {
    /// The candidate's derived member id.
    pub added_id: RaftNodeId,
    /// The candidate's membership record.
    pub added: MemberRecord,
    /// The slot's previous holder to remove in the same change, if the slot
    /// was occupied. `None` on first fill (bootstrap) or after the previous
    /// holder was already removed.
    pub evicted_id: Option<RaftNodeId>,
    /// The complete voter id set to commit: current voters, minus
    /// `evicted_id`, plus `added_id`.
    pub new_voter_ids: BTreeSet<RaftNodeId>,
    /// True when the candidate is ALREADY the slot's live voter (a repeated
    /// join request, e.g. a retry after a lost reply). The caller skips the
    /// membership change entirely; the plan's other fields describe the
    /// no-op result.
    pub already_member: bool,
}

/// Decide whether (and how) to admit `candidate` into slot `candidate_name`.
///
/// Pure: a deterministic function of the configured name set, the committed
/// voter map, and the request. The caller (the leader's join handler) then
/// executes the plan through openraft, which linearizes it.
///
/// SECURITY CONTRACT: `candidate_pubkey` MUST come from the candidate's
/// mutually-attested mesh channel
/// ([`PeerIdentity::mesh_pubkey`](crate::mesh::handshake::PeerIdentity)),
/// never from a request payload field. See the module docs.
///
/// Rules, in order:
/// 1. `candidate_name` must be a configured slot.
/// 2. The committed membership must satisfy the one-instance-per-slot and
///    id-derivation invariants (defence in depth; violations indicate a
///    wiring bug and refuse loudly).
/// 3. A candidate that IS already the slot's live voter is reported as
///    `already_member` (idempotent join; no change to commit).
/// 4. A candidate whose derived id equals a live voter of a DIFFERENT slot
///    is refused ([`AdmissionError::IdCollision`]).
/// 5. Otherwise: evict the slot's current holder (if any) and admit the
///    candidate, in one voter-set change.
pub fn plan_admission(
    configured_names: &BTreeSet<String>,
    voters: &BTreeMap<RaftNodeId, MemberRecord>,
    candidate_name: &str,
    candidate_pubkey: &[u8; CONTROL_PUBKEY_LEN],
) -> Result<AdmissionPlan, AdmissionError> {
    // 1. The slot must exist in the configured cluster shape.
    if !configured_names.contains(candidate_name) {
        return Err(AdmissionError::UnknownSlot(candidate_name.to_string()));
    }

    // 2. Committed-state invariants (defence in depth).
    for name in configured_names {
        let holders = voters.values().filter(|m| m.name == *name).count();
        if holders > 1 {
            return Err(AdmissionError::CorruptMembership(holders, name.clone()));
        }
    }
    for (id, member) in voters {
        if *id != instance_node_id(&member.pubkey) {
            return Err(AdmissionError::IdMismatch(*id));
        }
    }

    let added_id = instance_node_id(candidate_pubkey);
    let added = MemberRecord {
        name: candidate_name.to_string(),
        pubkey: *candidate_pubkey,
    };

    // The slot's current holder, if any.
    let slot_holder = voters
        .iter()
        .find(|(_, m)| m.name == candidate_name)
        .map(|(id, _)| *id);

    // 3. Idempotent re-join: the candidate already holds the slot.
    if slot_holder == Some(added_id) {
        return Ok(AdmissionPlan {
            added_id,
            added,
            evicted_id: None,
            new_voter_ids: voters.keys().copied().collect(),
            already_member: true,
        });
    }

    // 4. Truncated-hash collision with a live voter of another slot.
    if let Some(collided) = voters.get(&added_id) {
        // (slot_holder == added_id was handled above, so this voter holds a
        // different slot.)
        return Err(AdmissionError::IdCollision(collided.name.clone()));
    }

    // 5. Replace-on-rejoin: evict the slot's previous holder (if occupied)
    //    and admit the candidate in the same voter-set change.
    let mut new_voter_ids: BTreeSet<RaftNodeId> = voters.keys().copied().collect();
    if let Some(evicted) = slot_holder {
        new_voter_ids.remove(&evicted);
    }
    new_voter_ids.insert(added_id);

    debug_assert!(new_voter_ids.len() <= configured_names.len());

    Ok(AdmissionPlan {
        added_id,
        added,
        evicted_id: slot_holder,
        new_voter_ids,
        already_member: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> [u8; CONTROL_PUBKEY_LEN] {
        let mut out = [b; CONTROL_PUBKEY_LEN];
        out[0] = 0x04;
        out
    }

    fn names(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn voters(list: &[(&str, u8)]) -> BTreeMap<RaftNodeId, MemberRecord> {
        list.iter()
            .map(|(name, seed)| {
                let pubkey = pk(*seed);
                (
                    instance_node_id(&pubkey),
                    MemberRecord {
                        name: name.to_string(),
                        pubkey,
                    },
                )
            })
            .collect()
    }

    const CLUSTER: [&str; 3] = ["az-a", "az-b", "az-c"];

    /// Same pubkey, same id, on every node: the id is a pure function of the
    /// key. Different keys give different ids.
    #[test]
    fn id_is_deterministic_per_pubkey() {
        assert_eq!(instance_node_id(&pk(1)), instance_node_id(&pk(1)));
        assert_ne!(instance_node_id(&pk(1)), instance_node_id(&pk(2)));
    }

    /// First fill of an empty slot: no eviction, candidate joins the voter
    /// set.
    #[test]
    fn first_fill_admits_without_eviction() {
        let v = voters(&[("az-a", 1), ("az-b", 2)]);
        let plan = plan_admission(&names(&CLUSTER), &v, "az-c", &pk(3)).unwrap();
        assert_eq!(plan.evicted_id, None);
        assert!(!plan.already_member);
        assert!(plan.new_voter_ids.contains(&instance_node_id(&pk(3))));
        assert_eq!(plan.new_voter_ids.len(), 3);
    }

    /// A restart (fresh key, same slot) evicts the previous holder and admits
    /// the new instance in one change: at no committed point do two instances
    /// hold the slot.
    #[test]
    fn rejoin_replaces_previous_holder_atomically() {
        let v = voters(&[("az-a", 1), ("az-b", 2), ("az-c", 3)]);
        let plan = plan_admission(&names(&CLUSTER), &v, "az-b", &pk(0x22)).unwrap();
        assert_eq!(plan.evicted_id, Some(instance_node_id(&pk(2))));
        assert!(!plan.already_member);
        assert!(plan.new_voter_ids.contains(&instance_node_id(&pk(0x22))));
        assert!(!plan.new_voter_ids.contains(&instance_node_id(&pk(2))));
        assert_eq!(plan.new_voter_ids.len(), 3);
    }

    /// A clone flap (replace b1 with b2, then b1 asks again) is just another
    /// replacement: churn, never two holders.
    #[test]
    fn flapping_replacement_keeps_one_holder() {
        let mut v = voters(&[("az-a", 1), ("az-b", 2), ("az-c", 3)]);
        let plan = plan_admission(&names(&CLUSTER), &v, "az-b", &pk(0x22)).unwrap();
        // Apply the plan to the map (what the committed change does).
        if let Some(e) = plan.evicted_id {
            v.remove(&e);
        }
        v.insert(plan.added_id, plan.added.clone());
        // The displaced original asks to come back: admitted, evicting the
        // clone. Still exactly one az-b at each committed point.
        let back = plan_admission(&names(&CLUSTER), &v, "az-b", &pk(2)).unwrap();
        assert_eq!(back.evicted_id, Some(instance_node_id(&pk(0x22))));
        let holders = v.values().filter(|m| m.name == "az-b").count();
        assert_eq!(holders, 1);
    }

    /// A repeated join from the slot's live holder (retry after a lost
    /// reply) is idempotent: no membership change.
    #[test]
    fn rejoin_of_live_holder_is_idempotent() {
        let v = voters(&[("az-a", 1), ("az-b", 2), ("az-c", 3)]);
        let plan = plan_admission(&names(&CLUSTER), &v, "az-b", &pk(2)).unwrap();
        assert!(plan.already_member);
        assert_eq!(plan.evicted_id, None);
        assert_eq!(
            plan.new_voter_ids,
            v.keys().copied().collect::<BTreeSet<_>>()
        );
    }

    /// A slot name outside the configured cluster shape is refused: the
    /// cluster never grows past its three slots no matter how many attested
    /// same-image instances ask.
    #[test]
    fn unknown_slot_is_refused() {
        let v = voters(&[("az-a", 1)]);
        let err = plan_admission(&names(&CLUSTER), &v, "az-evil", &pk(9)).unwrap_err();
        assert_eq!(err, AdmissionError::UnknownSlot("az-evil".to_string()));
    }

    /// An id collision with a live voter of a different slot is refused
    /// rather than conflating two members.
    #[test]
    fn id_collision_with_other_slot_is_refused() {
        let v = voters(&[("az-a", 1), ("az-b", 2)]);
        // Same pubkey as az-a's live holder, but asking for az-b's slot.
        let err = plan_admission(&names(&CLUSTER), &v, "az-b", &pk(1)).unwrap_err();
        assert_eq!(err, AdmissionError::IdCollision("az-a".to_string()));
    }

    /// Corrupt committed state (two voters in one slot) is refused loudly
    /// instead of being silently repaired by an eviction guess.
    #[test]
    fn corrupt_membership_is_refused() {
        let mut v = voters(&[("az-a", 1), ("az-b", 2)]);
        let second = pk(0x33);
        v.insert(
            instance_node_id(&second),
            MemberRecord {
                name: "az-b".to_string(),
                pubkey: second,
            },
        );
        let err = plan_admission(&names(&CLUSTER), &v, "az-c", &pk(4)).unwrap_err();
        assert_eq!(
            err,
            AdmissionError::CorruptMembership(2, "az-b".to_string())
        );
    }

    /// A voter whose id does not derive from its recorded pubkey indicates a
    /// wiring bug; refused.
    #[test]
    fn id_mismatch_is_refused() {
        let mut v = voters(&[("az-a", 1)]);
        v.insert(
            42,
            MemberRecord {
                name: "az-b".to_string(),
                pubkey: pk(7),
            },
        );
        let err = plan_admission(&names(&CLUSTER), &v, "az-c", &pk(4)).unwrap_err();
        assert_eq!(err, AdmissionError::IdMismatch(42));
    }
}
