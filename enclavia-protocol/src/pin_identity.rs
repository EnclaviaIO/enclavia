//! Pin identity: the measurements that name an enclave's synchronizer pin
//! slot.
//!
//! The synchronizer keeps one pin slot per enclave identity. The identity
//! is the enclave's image measurements plus every user PCR:
//!
//! | Index    | Measures                                             |
//! |----------|------------------------------------------------------|
//! | PCR0     | enclave image file                                   |
//! | PCR1     | kernel and bootstrap                                 |
//! | PCR2     | application                                          |
//! | PCR16-31 | user PCRs: whatever the measured init extends and locks |
//!
//! Not included: PCR3 / PCR4 describe the parent instance (IAM role,
//! instance id) and change when the enclave is relaunched elsewhere; PCR8
//! is the EIF signing certificate, which Enclavia does not use.
//!
//! PCR0-2 are the same for every enclave built from the same image, so on
//! their own they cannot tell two such enclaves apart. Per-enclave data
//! (for example the enclave id and control key, or a recovery-mode flag)
//! goes into a user PCR, and because every user PCR is part of the
//! identity, a feature that uses one needs no synchronizer change.
//!
//! ## Rule for features that use a user PCR
//!
//! A feature must EXTEND and LOCK its user PCR before the enclave's first
//! synchronizer contact (nbd-client's boot verification). An attestation
//! document reports a user PCR only once it is locked (see "Absent and
//! zero" below), and a value that could still change would give the same
//! enclave a different identity later in its life.
//!
//! ## Absent and zero
//!
//! An NSM attestation document carries a map from PCR index to value. The
//! emulated NSM (QEMU `nitro-enclave`) puts a PCR in that map exactly when
//! it is locked, and the machine locks PCR0-15 at boot, so user PCRs 16-31
//! appear only once something locks them. The identity reads them as:
//!
//! * absent: the initial value, 48 zero bytes;
//! * present: its value, which must be exactly [`PCR_LEN`] bytes.
//!
//! A user PCR that is locked but never extended is present and zero, and so
//! gives the same identity as an absent one. An index of [`MAX_PCRS`] or
//! more, or a value of any other length, is a malformed document and is
//! rejected. PCR0-2 must be present.
//!
//! ## Canonical encoding and key
//!
//! ```text
//! canonical = PIN_IDENTITY_DST
//!          || PCR0 || PCR1 || PCR2 || PCR16 || PCR17 || ... || PCR31
//! key       = SHA-256(canonical)
//! ```
//!
//! Every PCR is fixed width ([`PCR_LEN`] = 48 bytes, SHA-384, the only
//! digest Nitro uses), in the order of [`PIN_IDENTITY_PCR_INDICES`], with
//! no length prefixes. The DST is 37 bytes, so `canonical` is always 949
//! bytes. The synchronizer's `PcrKey` is [`PinIdentity::key`].
//!
//! On the wire (CBOR in `UpgradePayload`, JSON wherever it is shown) an
//! identity is a map with exactly the 19 keys `PCR0`, `PCR1`, `PCR2`,
//! `PCR16` ... `PCR31`, in that order, each a 96-character hex string. All
//! keys are required and unknown keys are refused, so there is one
//! encoding per identity.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attestation::Pcrs;
use crate::chain::PcrsHex;

/// Length of one PCR value: SHA-384.
pub const PCR_LEN: usize = 48;

/// Number of PCRs an NSM exposes (`DescribeNSM.max_pcrs`). Valid indices
/// are `0..MAX_PCRS`.
pub const MAX_PCRS: usize = 32;

/// First user PCR index. User PCRs are `USER_PCR_FIRST..MAX_PCRS`.
pub const USER_PCR_FIRST: usize = 16;

/// Number of user PCRs (16-31).
pub const USER_PCR_COUNT: usize = MAX_PCRS - USER_PCR_FIRST;

/// The PCR indices that make up a pin identity, in canonical order.
pub const PIN_IDENTITY_PCR_INDICES: [usize; 19] = [
    0, 1, 2, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

/// Domain-separation prefix of the canonical encoding.
pub const PIN_IDENTITY_DST: &[u8] = b"enclavia/synchronizer/pin-identity/v1";

/// One PCR value.
pub type Pcr = [u8; PCR_LEN];

/// User PCRs 16-31 all at their initial value: what an enclave that locks
/// no user PCR reports.
pub const ZERO_USER_PCRS: [Pcr; USER_PCR_COUNT] = [[0u8; PCR_LEN]; USER_PCR_COUNT];

/// Why a set of PCR values is not a valid pin identity.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinIdentityError {
    /// PCR0, PCR1 or PCR2 is missing.
    #[error("PCR{0} is missing")]
    MissingImagePcr(usize),
    /// A PCR value is not [`PCR_LEN`] bytes.
    #[error("PCR{index} is {len} bytes, expected {PCR_LEN}")]
    BadLength {
        /// The PCR index.
        index: usize,
        /// The actual length in bytes.
        len: usize,
    },
    /// A PCR index is `MAX_PCRS` or more.
    #[error("PCR index {0} is out of range (max {MAX_PCRS} PCRs)")]
    IndexOutOfRange(usize),
    /// A hex-encoded PCR value does not decode.
    #[error("PCR{0} is not valid hex")]
    BadHex(usize),
}

/// An enclave's pin identity: PCR0, PCR1, PCR2 and user PCRs 16-31. See
/// the module docs for the rules and the canonical encoding.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PinIdentity {
    image: [Pcr; 3],
    user: [Pcr; USER_PCR_COUNT],
}

impl PinIdentity {
    /// Build from PCR0-2 and user PCRs 16-31 (index 0 of `user` is PCR16).
    pub fn new(image: [Pcr; 3], user: [Pcr; USER_PCR_COUNT]) -> Self {
        Self { image, user }
    }

    /// Build from the image PCRs of a [`Pcrs`] and the given user PCRs.
    /// Fails unless PCR0-2 are exactly [`PCR_LEN`] bytes.
    pub fn from_image_pcrs(
        pcrs: &Pcrs,
        user: [Pcr; USER_PCR_COUNT],
    ) -> Result<Self, PinIdentityError> {
        Ok(Self::new(
            [
                fixed(0, &pcrs.pcr0)?,
                fixed(1, &pcrs.pcr1)?,
                fixed(2, &pcrs.pcr2)?,
            ],
            user,
        ))
    }

    /// Build from an attestation document's PCR map, applying the
    /// absent / zero rule from the module docs: PCR0-2 are required,
    /// absent user PCRs are zero, every present value must be
    /// [`PCR_LEN`] bytes, and any index of [`MAX_PCRS`] or more is
    /// rejected. PCR3-15 are ignored apart from their length.
    pub fn from_doc_pcrs<V: AsRef<[u8]>>(
        pcrs: &BTreeMap<usize, V>,
    ) -> Result<Self, PinIdentityError> {
        for (&index, value) in pcrs {
            if index >= MAX_PCRS {
                return Err(PinIdentityError::IndexOutOfRange(index));
            }
            let len = value.as_ref().len();
            if len != PCR_LEN {
                return Err(PinIdentityError::BadLength { index, len });
            }
        }
        let image_pcr = |index: usize| -> Result<Pcr, PinIdentityError> {
            let value = pcrs
                .get(&index)
                .ok_or(PinIdentityError::MissingImagePcr(index))?;
            fixed(index, value.as_ref())
        };
        let image = [image_pcr(0)?, image_pcr(1)?, image_pcr(2)?];
        let mut user = ZERO_USER_PCRS;
        for (slot, value) in user.iter_mut().enumerate() {
            if let Some(v) = pcrs.get(&(USER_PCR_FIRST + slot)) {
                *value = fixed(USER_PCR_FIRST + slot, v.as_ref())?;
            }
        }
        Ok(Self { image, user })
    }

    /// PCR0, PCR1, PCR2.
    pub fn image(&self) -> &[Pcr; 3] {
        &self.image
    }

    /// User PCRs 16-31 (index 0 is PCR16).
    pub fn user(&self) -> &[Pcr; USER_PCR_COUNT] {
        &self.user
    }

    /// The value of PCR `index`, if it is part of the identity.
    pub fn pcr(&self, index: usize) -> Option<&Pcr> {
        match index {
            0..=2 => Some(&self.image[index]),
            USER_PCR_FIRST..MAX_PCRS => Some(&self.user[index - USER_PCR_FIRST]),
            _ => None,
        }
    }

    /// The same identity with different user PCRs.
    pub fn with_user_pcrs(&self, user: [Pcr; USER_PCR_COUNT]) -> Self {
        Self {
            image: self.image,
            user,
        }
    }

    /// PCR0-2 as a [`Pcrs`], for checks that pin only the image (SDK
    /// connections, KMS key policies, the chain's boot links).
    pub fn image_pcrs(&self) -> Pcrs {
        Pcrs {
            pcr0: self.image[0].to_vec(),
            pcr1: self.image[1].to_vec(),
            pcr2: self.image[2].to_vec(),
        }
    }

    /// PCR0-2 in the chain's hex form.
    pub fn image_pcrs_hex(&self) -> PcrsHex {
        PcrsHex {
            pcr0: hex::encode(self.image[0]),
            pcr1: hex::encode(self.image[1]),
            pcr2: hex::encode(self.image[2]),
        }
    }

    /// The user PCRs that are not zero, as `(index, value)`.
    pub fn nonzero_user_pcrs(&self) -> impl Iterator<Item = (usize, &Pcr)> {
        self.user
            .iter()
            .enumerate()
            .filter(|(_, v)| v.iter().any(|b| *b != 0))
            .map(|(slot, v)| (USER_PCR_FIRST + slot, v))
    }

    /// The canonical encoding: [`PIN_IDENTITY_DST`] followed by the 19
    /// PCRs in [`PIN_IDENTITY_PCR_INDICES`] order, 48 bytes each.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(PIN_IDENTITY_DST.len() + PIN_IDENTITY_PCR_INDICES.len() * PCR_LEN);
        out.extend_from_slice(PIN_IDENTITY_DST);
        for pcr in self.image.iter().chain(self.user.iter()) {
            out.extend_from_slice(pcr);
        }
        out
    }

    /// SHA-256 of [`Self::canonical_bytes`]: the synchronizer's pin-slot
    /// key (`PcrKey`).
    pub fn key(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

impl fmt::Debug for PinIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("PinIdentity");
        s.field("PCR0", &hex::encode(self.image[0]))
            .field("PCR1", &hex::encode(self.image[1]))
            .field("PCR2", &hex::encode(self.image[2]));
        let nonzero: Vec<(usize, String)> = self
            .nonzero_user_pcrs()
            .map(|(i, v)| (i, hex::encode(v)))
            .collect();
        s.field("nonzero_user_pcrs", &nonzero).finish()
    }
}

fn fixed(index: usize, value: &[u8]) -> Result<Pcr, PinIdentityError> {
    value.try_into().map_err(|_| PinIdentityError::BadLength {
        index,
        len: value.len(),
    })
}

fn from_hex(index: usize, s: &str) -> Result<Pcr, PinIdentityError> {
    let bytes = hex::decode(s).map_err(|_| PinIdentityError::BadHex(index))?;
    fixed(index, &bytes)
}

/// Wire form of [`PinIdentity`]: every identity PCR, hex, under its
/// nitro-cli style name. Field order is the canonical order, so the CBOR
/// map is deterministic.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinIdentityWire {
    #[serde(rename = "PCR0")]
    pcr0: String,
    #[serde(rename = "PCR1")]
    pcr1: String,
    #[serde(rename = "PCR2")]
    pcr2: String,
    #[serde(rename = "PCR16")]
    pcr16: String,
    #[serde(rename = "PCR17")]
    pcr17: String,
    #[serde(rename = "PCR18")]
    pcr18: String,
    #[serde(rename = "PCR19")]
    pcr19: String,
    #[serde(rename = "PCR20")]
    pcr20: String,
    #[serde(rename = "PCR21")]
    pcr21: String,
    #[serde(rename = "PCR22")]
    pcr22: String,
    #[serde(rename = "PCR23")]
    pcr23: String,
    #[serde(rename = "PCR24")]
    pcr24: String,
    #[serde(rename = "PCR25")]
    pcr25: String,
    #[serde(rename = "PCR26")]
    pcr26: String,
    #[serde(rename = "PCR27")]
    pcr27: String,
    #[serde(rename = "PCR28")]
    pcr28: String,
    #[serde(rename = "PCR29")]
    pcr29: String,
    #[serde(rename = "PCR30")]
    pcr30: String,
    #[serde(rename = "PCR31")]
    pcr31: String,
}

impl Serialize for PinIdentity {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let h = |p: &Pcr| hex::encode(p);
        let u = &self.user;
        PinIdentityWire {
            pcr0: h(&self.image[0]),
            pcr1: h(&self.image[1]),
            pcr2: h(&self.image[2]),
            pcr16: h(&u[0]),
            pcr17: h(&u[1]),
            pcr18: h(&u[2]),
            pcr19: h(&u[3]),
            pcr20: h(&u[4]),
            pcr21: h(&u[5]),
            pcr22: h(&u[6]),
            pcr23: h(&u[7]),
            pcr24: h(&u[8]),
            pcr25: h(&u[9]),
            pcr26: h(&u[10]),
            pcr27: h(&u[11]),
            pcr28: h(&u[12]),
            pcr29: h(&u[13]),
            pcr30: h(&u[14]),
            pcr31: h(&u[15]),
        }
        .serialize(ser)
    }
}

impl<'de> Deserialize<'de> for PinIdentity {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let w = PinIdentityWire::deserialize(de)?;
        let user_hex = [
            &w.pcr16, &w.pcr17, &w.pcr18, &w.pcr19, &w.pcr20, &w.pcr21, &w.pcr22, &w.pcr23,
            &w.pcr24, &w.pcr25, &w.pcr26, &w.pcr27, &w.pcr28, &w.pcr29, &w.pcr30, &w.pcr31,
        ];
        let decode = || -> Result<PinIdentity, PinIdentityError> {
            let image = [
                from_hex(0, &w.pcr0)?,
                from_hex(1, &w.pcr1)?,
                from_hex(2, &w.pcr2)?,
            ];
            let mut user = ZERO_USER_PCRS;
            for (slot, s) in user_hex.iter().enumerate() {
                user[slot] = from_hex(USER_PCR_FIRST + slot, s)?;
            }
            Ok(PinIdentity { image, user })
        };
        decode().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(a: u8, b: u8, c: u8) -> [Pcr; 3] {
        [[a; PCR_LEN], [b; PCR_LEN], [c; PCR_LEN]]
    }

    fn with_user(index: usize, byte: u8) -> [Pcr; USER_PCR_COUNT] {
        let mut user = ZERO_USER_PCRS;
        user[index - USER_PCR_FIRST] = [byte; PCR_LEN];
        user
    }

    /// Test vectors. The expected keys were computed outside this crate:
    /// `printf 'enclavia/synchronizer/pin-identity/v1'` followed by the 19
    /// PCRs as raw bytes, piped through `sha256sum`.
    #[test]
    fn key_test_vectors() {
        let cases: [(&str, PinIdentity, &str); 4] = [
            (
                "all zero",
                PinIdentity::new(image(0, 0, 0), ZERO_USER_PCRS),
                "7f554eb8245333b915197463161a58a0d08fd92f1dfc21e22df2cc24ca6e9b86",
            ),
            (
                "PCR0-2 = 01/02/03, user PCRs zero",
                PinIdentity::new(image(1, 2, 3), ZERO_USER_PCRS),
                "709f519753e0737bb745a04354ebf87b32bb090ad473ea6e23c0f731ed676d84",
            ),
            (
                "as above, PCR16 = 10",
                PinIdentity::new(image(1, 2, 3), with_user(16, 0x10)),
                "fa843d35054e93e029f00f74bc3ab97e1fccded894c3bf211668fbee33cffb71",
            ),
            (
                "as above, PCR31 = ff",
                PinIdentity::new(image(1, 2, 3), with_user(31, 0xff)),
                "be9986dda4b2aded0dd812f70d629e591f8ac0171226dc791b4990af9261e4c1",
            ),
        ];
        for (name, id, expected) in cases {
            assert_eq!(id.canonical_bytes().len(), 949, "{name}");
            assert_eq!(hex::encode(id.key()), expected, "{name}");
        }
    }

    #[test]
    fn canonical_bytes_layout() {
        let id = PinIdentity::new(image(1, 2, 3), with_user(17, 0xaa));
        let bytes = id.canonical_bytes();
        assert_eq!(&bytes[..PIN_IDENTITY_DST.len()], PIN_IDENTITY_DST);
        let pcrs = &bytes[PIN_IDENTITY_DST.len()..];
        for (pos, &index) in PIN_IDENTITY_PCR_INDICES.iter().enumerate() {
            let chunk = &pcrs[pos * PCR_LEN..(pos + 1) * PCR_LEN];
            assert_eq!(chunk, id.pcr(index).unwrap(), "PCR{index}");
        }
    }

    #[test]
    fn same_image_different_user_pcr_is_a_different_key() {
        let a = PinIdentity::new(image(1, 2, 3), with_user(16, 0x01));
        let b = PinIdentity::new(image(1, 2, 3), with_user(16, 0x02));
        assert_eq!(a.image_pcrs(), b.image_pcrs());
        assert_ne!(a.key(), b.key());
    }

    fn doc_map(entries: &[(usize, Vec<u8>)]) -> BTreeMap<usize, Vec<u8>> {
        entries.iter().cloned().collect()
    }

    /// The PCR map a QEMU nitro-enclave document carries when nothing
    /// locked a user PCR: PCR0-15.
    fn qemu_default_map() -> BTreeMap<usize, Vec<u8>> {
        let mut m: BTreeMap<usize, Vec<u8>> = (0..16).map(|i| (i, vec![0u8; PCR_LEN])).collect();
        m.insert(0, vec![1; PCR_LEN]);
        m.insert(1, vec![2; PCR_LEN]);
        m.insert(2, vec![3; PCR_LEN]);
        m
    }

    #[test]
    fn absent_user_pcrs_are_zero() {
        let id = PinIdentity::from_doc_pcrs(&qemu_default_map()).unwrap();
        assert_eq!(id, PinIdentity::new(image(1, 2, 3), ZERO_USER_PCRS));
    }

    #[test]
    fn locked_zero_user_pcr_equals_absent() {
        let mut m = qemu_default_map();
        m.insert(20, vec![0; PCR_LEN]);
        let absent = PinIdentity::from_doc_pcrs(&qemu_default_map()).unwrap();
        assert_eq!(PinIdentity::from_doc_pcrs(&m).unwrap(), absent);
    }

    #[test]
    fn present_user_pcr_is_read() {
        let mut m = qemu_default_map();
        m.insert(16, vec![0x10; PCR_LEN]);
        let id = PinIdentity::from_doc_pcrs(&m).unwrap();
        assert_eq!(id, PinIdentity::new(image(1, 2, 3), with_user(16, 0x10)));
    }

    #[test]
    fn short_user_pcr_is_rejected() {
        let mut m = qemu_default_map();
        m.insert(16, vec![0x10; PCR_LEN - 1]);
        assert_eq!(
            PinIdentity::from_doc_pcrs(&m),
            Err(PinIdentityError::BadLength {
                index: 16,
                len: PCR_LEN - 1
            })
        );
    }

    #[test]
    fn empty_user_pcr_is_rejected() {
        let mut m = qemu_default_map();
        m.insert(31, Vec::new());
        assert_eq!(
            PinIdentity::from_doc_pcrs(&m),
            Err(PinIdentityError::BadLength { index: 31, len: 0 })
        );
    }

    #[test]
    fn index_past_max_pcrs_is_rejected() {
        let mut m = qemu_default_map();
        m.insert(32, vec![0; PCR_LEN]);
        assert_eq!(
            PinIdentity::from_doc_pcrs(&m),
            Err(PinIdentityError::IndexOutOfRange(32))
        );
    }

    #[test]
    fn missing_image_pcr_is_rejected() {
        let m = doc_map(&[(0, vec![1; PCR_LEN]), (1, vec![2; PCR_LEN])]);
        assert_eq!(
            PinIdentity::from_doc_pcrs(&m),
            Err(PinIdentityError::MissingImagePcr(2))
        );
    }

    #[test]
    fn non_sha384_image_pcr_is_rejected() {
        let mut m = qemu_default_map();
        m.insert(0, vec![1; 32]);
        assert_eq!(
            PinIdentity::from_doc_pcrs(&m),
            Err(PinIdentityError::BadLength { index: 0, len: 32 })
        );
    }

    #[test]
    fn cbor_round_trip_and_key_names() {
        let id = PinIdentity::new(image(1, 2, 3), with_user(16, 0x10));
        let mut bytes = Vec::new();
        ciborium::into_writer(&id, &mut bytes).unwrap();
        let back: PinIdentity = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back, id);

        let json = serde_json::to_value(&id).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 19);
        for index in PIN_IDENTITY_PCR_INDICES {
            let v = obj[&format!("PCR{index}")].as_str().unwrap();
            assert_eq!(v, hex::encode(id.pcr(index).unwrap()));
        }
    }

    #[test]
    fn wire_form_requires_every_pcr() {
        let id = PinIdentity::new(image(1, 2, 3), ZERO_USER_PCRS);
        let mut json = serde_json::to_value(&id).unwrap();
        json.as_object_mut().unwrap().remove("PCR31");
        assert!(serde_json::from_value::<PinIdentity>(json).is_err());
    }

    #[test]
    fn wire_form_rejects_unknown_pcrs() {
        let id = PinIdentity::new(image(1, 2, 3), ZERO_USER_PCRS);
        let mut json = serde_json::to_value(&id).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("PCR3".into(), hex::encode([0u8; PCR_LEN]).into());
        assert!(serde_json::from_value::<PinIdentity>(json).is_err());
    }

    #[test]
    fn wire_form_rejects_short_pcr() {
        let id = PinIdentity::new(image(1, 2, 3), ZERO_USER_PCRS);
        let mut json = serde_json::to_value(&id).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("PCR16".into(), hex::encode([0u8; PCR_LEN - 1]).into());
        assert!(serde_json::from_value::<PinIdentity>(json).is_err());
    }
}
