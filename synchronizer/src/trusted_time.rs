//! The node's trusted "now" for time-gated decisions.
//!
//! Enclaves have no clock synchronisation of their own, so the system clock
//! is not an input to any security decision. When the node needs the current
//! time to decide something (today: the `valid_from` gate on a `Transition`
//! link, see [`crate::wire::verify_transition_link`]), it requests a fresh
//! attestation document from its OWN `/dev/nsm` and reads the `timestamp` the
//! Nitro hypervisor stamped into it. Neither the parent instance nor a
//! drifting enclave clock can move that value. One NSM round trip takes about
//! a millisecond, and the callers are rare (one per `Transition`), so the
//! value is read fresh every time and never cached.
//!
//! Which source is used is fixed at compile time:
//!
//! * `enclave` builds (real Nitro, and QEMU via `qemu`, whose emulated NSM
//!   stamps whole seconds of the QEMU host clock) read `/dev/nsm`.
//! * Every other build (the `debug` UDS dev listener and the in-process
//!   tests) has no `/dev/nsm` and reads the system clock. Those builds also
//!   accept synthetic attestation documents, so they carry no security
//!   claim for the clock to weaken.

/// Current trusted time in milliseconds since the Unix epoch.
///
/// Fails closed: an error means the caller must refuse the time-gated
/// operation, never fall back to the system clock.
#[cfg(feature = "enclave")]
pub async fn now_ms() -> Result<u64, String> {
    tokio::task::spawn_blocking(|| {
        let doc = crate::mesh::attestation::request_own_attestation(None, None)
            .map_err(|e| e.to_string())?;
        enclavia_protocol::attestation::extract_own_timestamp_ms(&doc).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("nsm time task panicked: {e}"))?
}

/// Current time in milliseconds since the Unix epoch, from the system clock.
/// Non-enclave builds only (see the module docs).
#[cfg(not(feature = "enclave"))]
pub async fn now_ms() -> Result<u64, String> {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("system clock before the Unix epoch: {e}"))?;
    u64::try_from(since_epoch.as_millis()).map_err(|e| format!("system clock overflow: {e}"))
}
