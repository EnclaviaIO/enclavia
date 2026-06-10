//! NSM attestation wrapper for chain-init.
//!
//! Mirrors `enclavia-server::attestation` but tailored to the chain
//! link's binding: `user_data = sha256(payload)` (vs the server's
//! `user_data = control_pubkey`), and we also need the PCRs so the
//! payload can carry them verbatim. The verifier (the backend) reads
//! PCRs back off the attestation document on its side, so the two
//! sources have to agree; reading both from NSM here is the simplest
//! way to keep them in sync.

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

/// Raw PCR bytes read off NSM. Same byte length the EIF measures
/// (48-byte SHA-384 on Nitro / nitro-enclave QEMU).
pub struct Pcrs {
    pub pcr0: Vec<u8>,
    pub pcr1: Vec<u8>,
    pub pcr2: Vec<u8>,
}

/// RAII wrapper around the NSM driver fd. The `nsm_exit` call is
/// best-effort: the fd is process-scoped and reaped on exit either
/// way.
pub struct Nsm {
    fd: i32,
}

impl Drop for Nsm {
    fn drop(&mut self) {
        if self.fd >= 0 {
            nsm_exit(self.fd);
        }
    }
}

impl Nsm {
    pub fn open() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let fd = nsm_init();
        if fd < 0 {
            return Err("nsm_init returned a negative fd: /dev/nsm missing or unreadable".into());
        }
        Ok(Self { fd })
    }

    /// Pull PCR0/1/2 off NSM via `DescribePCR`. We do it eagerly rather
    /// than later from the attestation document because the attestation
    /// document doesn't expose PCRs in a typed shape (they're nested in
    /// CBOR), and the BootPayload needs them serialised as hex strings.
    pub fn read_pcrs(&self) -> Result<Pcrs, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Pcrs {
            pcr0: self.read_one_pcr(0)?,
            pcr1: self.read_one_pcr(1)?,
            pcr2: self.read_one_pcr(2)?,
        })
    }

    fn read_one_pcr(
        &self,
        index: u16,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let request = Request::DescribePCR { index };
        match nsm_process_request(self.fd, request) {
            Response::DescribePCR { lock: _, data } => Ok(data),
            Response::Error(error) => {
                Err(format!("NSM DescribePCR({index}) error: {error:?}").into())
            }
            other => Err(format!("NSM DescribePCR({index}) unexpected response: {other:?}").into()),
        }
    }

    /// Produce an attestation document binding the chain payload.
    ///
    /// `user_data` is the 32-byte sha256(payload) the backend's
    /// `verify_chain_attestation` reads back to confirm the chain link
    /// is well-formed. `nonce` is the same 32 random bytes the
    /// BootPayload carries (the chain ingest verifier doesn't check the
    /// document's nonce, but populating it with the payload's nonce
    /// avoids a slot whose value would otherwise be undefined).
    pub fn attest(
        &self,
        user_data: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let request = Request::Attestation {
            user_data: Some(user_data.to_vec().into()),
            nonce: Some(nonce.to_vec().into()),
            public_key: None,
        };
        match nsm_process_request(self.fd, request) {
            Response::Attestation { document } => Ok(document),
            Response::Error(error) => Err(format!("NSM Attestation error: {error:?}").into()),
            other => Err(format!("NSM Attestation unexpected response: {other:?}").into()),
        }
    }
}
