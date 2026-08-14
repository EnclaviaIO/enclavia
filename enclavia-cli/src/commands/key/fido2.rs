//! FIDO2 key-generation and index-recovery commands.

#[cfg(feature = "fido2")]
use base64::Engine as _;
use serde::Serialize;

use crate::error::CliError;
#[cfg(feature = "fido2")]
use crate::keys::{self, KeyBackend, KeyEntry};

/// Result of `key generate --fido2`.
#[derive(Debug, Clone, Serialize)]
pub struct GeneratedFido2Key {
    pub name: String,
    #[serde(rename = "type")]
    pub backend: String,
    /// Base64 discoverable credential identifier.
    pub credential_id: String,
    /// Authenticator model identifier.
    pub aaguid: String,
    /// Base64 65-byte uncompressed SEC1 P-256 public key.
    pub public_key: String,
    pub fingerprint: String,
}

/// Flags for `key generate --fido2`.
#[derive(Debug, Clone)]
pub struct Fido2GenerateArgs {
    pub name: String,
}

#[cfg(feature = "fido2")]
fn format_aaguid(aaguid: &[u8; 16]) -> String {
    let hex: String = aaguid.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Create a modern, discoverable CTAP2 ES256 credential and persist its
/// public metadata.
#[cfg(feature = "fido2")]
pub fn generate_fido2(args: &Fido2GenerateArgs) -> Result<GeneratedFido2Key, CliError> {
    let mut index = keys::load_index()?;
    keys::validate_name(&args.name)?;
    if index.keys.contains_key(&args.name) {
        return Err(CliError::Other(format!(
            "a key named {:?} already exists; pick another --name",
            args.name
        )));
    }

    let registered = crate::signer::register_fido2_credential(&args.name)?;
    let credential_id = base64::engine::general_purpose::STANDARD.encode(&registered.credential_id);
    let public_key = base64::engine::general_purpose::STANDARD.encode(registered.public_key);
    let aaguid = format_aaguid(&registered.aaguid);
    index.insert_new(
        &args.name,
        KeyEntry {
            public_key: public_key.clone(),
            backend: KeyBackend::Fido2 {
                credential_id: credential_id.clone(),
                aaguid: Some(aaguid.clone()),
            },
        },
    )?;
    if let Err(error) = keys::save_index(&index) {
        return Err(CliError::Other(format!(
            "the FIDO2 credential was created, but saving {} failed: {error}. Preserve this \
             non-secret recovery data before retrying: name={:?}, credential_id={}, aaguid={}, \
             public_key={}",
            keys::index_path().display(),
            args.name,
            credential_id,
            aaguid,
            public_key,
        )));
    }

    Ok(GeneratedFido2Key {
        name: args.name.clone(),
        backend: "fido2".into(),
        credential_id,
        aaguid,
        public_key,
        fingerprint: keys::fingerprint(&registered.public_key),
    })
}

#[cfg(not(feature = "fido2"))]
pub fn generate_fido2(_args: &Fido2GenerateArgs) -> Result<GeneratedFido2Key, CliError> {
    Err(CliError::Other(
        "this enclavia build was compiled without FIDO2 support; rebuild enclavia-cli with \
         the default `fido2` feature"
            .into(),
    ))
}

/// Flags for `key import --fido2`.
#[derive(Debug, Clone)]
pub struct Fido2ImportArgs {
    /// Local index name and the user name stored with the discoverable
    /// credential.
    pub name: String,
}

/// Result of recovering a discoverable FIDO2 credential into the local
/// index.
#[derive(Debug, Clone, Serialize)]
pub struct ImportedFido2Key {
    pub name: String,
    #[serde(rename = "type")]
    pub backend: String,
    pub credential_id: String,
    pub aaguid: String,
    pub public_key: String,
    pub fingerprint: String,
    /// Name of an existing index entry with the same public key, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub already_registered_as: Option<String>,
}

/// Rebuild the local index entry for a discoverable FIDO2 credential.
/// Credential management is PIN/UV protected and returns only public
/// metadata; the private key remains on the authenticator.
#[cfg(feature = "fido2")]
pub fn import_fido2(args: &Fido2ImportArgs) -> Result<ImportedFido2Key, CliError> {
    let mut index = keys::load_index()?;
    keys::validate_name(&args.name)?;
    if index.keys.contains_key(&args.name) {
        return Err(CliError::Other(format!(
            "a key named {:?} already exists in {}; FIDO2 import only rebuilds a missing index \
             entry",
            args.name,
            keys::index_path().display()
        )));
    }

    let recovered = crate::signer::recover_fido2_credential(&args.name)?;
    let already_registered_as = index
        .find_by_public_key(&recovered.public_key)
        .map(|(name, _)| name.to_string());
    let credential_id = base64::engine::general_purpose::STANDARD.encode(&recovered.credential_id);
    let public_key = base64::engine::general_purpose::STANDARD.encode(recovered.public_key);
    let aaguid = format_aaguid(&recovered.aaguid);
    index.insert_new(
        &args.name,
        KeyEntry {
            public_key: public_key.clone(),
            backend: KeyBackend::Fido2 {
                credential_id: credential_id.clone(),
                aaguid: Some(aaguid.clone()),
            },
        },
    )?;
    keys::save_index(&index)?;

    Ok(ImportedFido2Key {
        name: args.name.clone(),
        backend: "fido2".into(),
        credential_id,
        aaguid,
        public_key,
        fingerprint: keys::fingerprint(&recovered.public_key),
        already_registered_as,
    })
}

#[cfg(not(feature = "fido2"))]
pub fn import_fido2(_args: &Fido2ImportArgs) -> Result<ImportedFido2Key, CliError> {
    Err(CliError::Other(
        "this enclavia build was compiled without FIDO2 support; rebuild enclavia-cli with \
         the default `fido2` feature"
            .into(),
    ))
}
