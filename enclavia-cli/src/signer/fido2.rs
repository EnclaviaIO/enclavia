//! Vendor-neutral CTAP2 backend for USB HID FIDO2 authenticators.
//!
//! CTAP1 fallback is deliberately disabled on both credential
//! creation and assertion. Credentials use ES256, are scoped to
//! Enclavia's fixed RP ID, require user presence and verification,
//! and are discoverable so their public metadata can be recovered
//! from the authenticator if the local key index is lost.

use std::io::{BufRead as _, Write as _};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;

use authenticator::authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs};
use authenticator::crypto::{COSEAlgorithm, COSEKey, COSEKeyType, Curve};
use authenticator::ctap2::attestation::AuthenticatorDataFlags;
use authenticator::ctap2::commands::credential_management::CredentialList;
use authenticator::ctap2::server::{
    AuthenticationExtensionsClientInputs, CredentialProtectionPolicy,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters, PublicKeyCredentialUserEntity,
    RelyingParty, ResidentKeyRequirement, Transport, UserVerificationRequirement,
};
use authenticator::statecallback::StateCallback;
use authenticator::{
    AuthenticatorInfo, CredManagementCmd, CredentialManagementResult, InteractiveRequest,
    InteractiveUpdate, Pin, StatusPinUv, StatusUpdate,
};
use enclavia_protocol::custody::{
    FIDO2_ORIGIN, FIDO2_RP_ID, Fido2Assertion, check_fido2_sign_count, fido2_client_data_hash,
    verify_control_proof,
};
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};

use super::ControlSigner;
use crate::error::CliError;

const OPERATION_TIMEOUT_MS: u64 = 60_000;
const FIDO2_REGISTRATION_CLIENT_DATA_CONTEXT: &[u8] = b"enclavia-control-fido2-registration-v1\0";
const CONFIGURED_USER_VERIFICATION: &str =
    "configured user verification (`clientPin` or built-in `uv`)";

/// Public material returned by a successful CTAP2
/// `authenticatorMakeCredential` operation.
#[derive(Debug, Clone)]
pub struct RegisteredFido2Credential {
    pub credential_id: Vec<u8>,
    pub public_key: [u8; 65],
    pub aaguid: [u8; 16],
}

/// Public metadata recovered from a discoverable credential through
/// CTAP2 credential management.
#[derive(Debug, Clone)]
pub struct RecoveredFido2Credential {
    pub credential_id: Vec<u8>,
    pub public_key: [u8; 65],
    pub aaguid: [u8; 16],
}

fn new_service() -> Result<AuthenticatorService, CliError> {
    let mut service = AuthenticatorService::new()
        .map_err(|e| CliError::Other(format!("initializing FIDO2 service: {e}")))?;
    service.add_u2f_usb_hid_platform_transports();
    Ok(service)
}

fn missing_recoverable_profile_capabilities(info: &AuthenticatorInfo) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !info.options.resident_key {
        missing.push("discoverable credentials (`rk`)");
    }
    if !info.options.user_presence {
        missing.push("user presence (`up`)");
    }
    if info.options.client_pin != Some(true) && info.options.user_verification != Some(true) {
        missing.push(CONFIGURED_USER_VERIFICATION);
    }
    if !info.supports_cred_protect() {
        missing.push("`credProtect=UserVerificationRequired`");
    }
    if info.options.cred_mgmt != Some(true) && info.options.credential_mgmt_preview != Some(true) {
        missing.push("CTAP2 credential management");
    }
    if info.algorithms.as_ref().is_some_and(|algorithms| {
        !algorithms
            .iter()
            .any(|parameters| parameters.alg == COSEAlgorithm::ES256)
    }) {
        missing.push("ES256 credential creation");
    }
    missing
}

fn validate_recoverable_profile(info: &AuthenticatorInfo) -> Result<(), CliError> {
    let missing = missing_recoverable_profile_capabilities(info);
    if missing.is_empty() {
        return Ok(());
    }

    let versions = if info.versions.is_empty() {
        "not reported".to_string()
    } else {
        info.versions
            .iter()
            .map(|version| format!("{version:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    if missing.as_slice() == [CONFIGURED_USER_VERIFICATION]
        && info.options.client_pin == Some(false)
    {
        return Err(CliError::Other(format!(
            "selected authenticator supports Enclavia's recoverable FIDO2 profile, but it \
             does not have a FIDO2 PIN configured ({:?}; versions: {versions}). Set a FIDO2 \
             PIN on the authenticator, then retry. For a YubiKey, run \
             `ykman fido access change-pin`; the FIDO2 PIN is separate from the PIV PIN.",
            info.aaguid
        )));
    }

    Err(CliError::Other(format!(
        "selected authenticator does not support Enclavia's recoverable FIDO2 profile \
         ({:?}; versions: {versions}); missing: {}. Enclavia requires discoverable \
         credentials, configured user verification, credProtect, and CTAP2 credential \
         management so `key import --fido2` can reconstruct the local index.",
        info.aaguid,
        missing.join(", ")
    )))
}

fn capability_preflight_status_loop(
    status: Receiver<StatusUpdate>,
    selected_info: Sender<Result<AuthenticatorInfo, CliError>>,
) {
    let mut reported = false;

    while let Ok(update) = status.recv() {
        match update {
            StatusUpdate::PresenceRequired => {
                eprintln!("Touch or confirm on your FIDO2 security key...");
            }
            StatusUpdate::SelectDeviceNotice => {
                eprintln!(
                    "Multiple FIDO2 security keys found; touch the one whose capabilities \
                     should be checked..."
                );
            }
            StatusUpdate::InteractiveManagement(InteractiveUpdate::StartManagement((
                request,
                info,
            ))) if !reported => {
                let result = match request.send(InteractiveRequest::Quit) {
                    Ok(()) => info.ok_or_else(|| {
                        CliError::Other("selected authenticator does not support CTAP2".into())
                    }),
                    Err(_) => Err(CliError::Other(
                        "FIDO2 capability inspection ended before it could be completed".into(),
                    )),
                };
                let _ = selected_info.send(result);
                reported = true;
            }
            StatusUpdate::SelectResultNotice(sender, _) => {
                let _ = sender.send(None);
            }
            _ => {}
        }
    }

    if !reported {
        let _ = selected_info.send(Err(CliError::Other(
            "FIDO2 capability inspection ended without device information".into(),
        )));
    }
}

fn preflight_recoverable_profile(service: &mut AuthenticatorService) -> Result<(), CliError> {
    let (status_tx, status_rx) = channel();
    let (info_tx, info_rx) = channel();
    let status_thread = thread::spawn(move || capability_preflight_status_loop(status_rx, info_tx));
    let (result_tx, result_rx) = channel();
    let callback = StateCallback::new(Box::new(move |result| {
        let _ = result_tx.send(result);
    }));

    eprintln!("Checking the FIDO2 authenticator's recoverable-credential capabilities.");
    let started = service.manage(OPERATION_TIMEOUT_MS, status_tx.clone(), callback);
    drop(status_tx);
    if let Err(error) = started {
        let _ = service.cancel();
        let _ = status_thread.join();
        return Err(CliError::Other(format!(
            "checking FIDO2 authenticator capabilities: {error}"
        )));
    }

    let management = result_rx.recv();
    // `AuthenticatorService` retains the completed transaction until
    // it is explicitly cancelled or replaced by another operation.
    // Cancel before joining so the transaction drops its status sender
    // immediately instead of keeping this thread alive until timeout.
    let _ = service.cancel();
    let _ = status_thread.join();
    management
        .map_err(|error| {
            CliError::Other(format!(
                "checking FIDO2 authenticator capabilities: result channel closed: {error}"
            ))
        })?
        .map_err(|error| {
            CliError::Other(format!(
                "checking FIDO2 authenticator capabilities: {error}"
            ))
        })?;
    let info = info_rx.recv().map_err(|error| {
        CliError::Other(format!(
            "checking FIDO2 authenticator capabilities: no device information returned: \
             {error}"
        ))
    })??;
    validate_recoverable_profile(&info)
}

fn prompt_pin() -> Result<String, CliError> {
    eprint!("FIDO2 security-key PIN (input hidden; press Enter when done): ");
    std::io::stderr()
        .flush()
        .map_err(|e| CliError::Other(format!("flushing stderr: {e}")))?;
    let pin = rpassword::read_password()
        .map_err(|e| CliError::Other(format!("reading FIDO2 PIN: {e}")))?;
    if pin.is_empty() {
        return Err(CliError::Other("empty FIDO2 PIN".into()));
    }
    Ok(pin)
}

type PinCache = Arc<Mutex<Option<Pin>>>;

fn send_pin(sender: Sender<Pin>, cache: Option<&PinCache>, reuse_cached: bool) {
    if reuse_cached {
        if let Some(pin) =
            cache.and_then(|cache| cache.lock().expect("poisoned FIDO2 PIN cache").clone())
        {
            let _ = sender.send(pin);
            return;
        }
    } else if let Some(cache) = cache {
        *cache.lock().expect("poisoned FIDO2 PIN cache") = None;
    }

    match prompt_pin() {
        Ok(pin) => {
            let pin = Pin::new(&pin);
            if let Some(cache) = cache {
                *cache.lock().expect("poisoned FIDO2 PIN cache") = Some(pin.clone());
            }
            if sender.send(pin).is_err() {
                eprintln!("FIDO2 operation ended before the PIN was submitted.");
            }
        }
        Err(e) => {
            // Dropping the response sender cancels the pending
            // operation inside authenticator-rs.
            eprintln!("FIDO2 PIN prompt failed: {e}");
        }
    }
}

fn parse_result_selection(input: &str, choices: usize) -> Result<Option<usize>, ()> {
    match input.trim().parse::<usize>() {
        Ok(0) => Ok(None),
        Ok(choice) if choice <= choices => Ok(Some(choice - 1)),
        _ => Err(()),
    }
}

fn prompt_result_selection(users: &[PublicKeyCredentialUserEntity]) -> Option<usize> {
    if users.is_empty() {
        eprintln!("Authenticator returned multiple assertions without selectable users.");
        return None;
    }

    eprintln!("Authenticator returned multiple matching credentials. Select one:");
    for (index, user) in users.iter().enumerate() {
        let label = user
            .display_name
            .as_deref()
            .or(user.name.as_deref())
            .unwrap_or("unnamed credential");
        eprintln!("  {}) {label}", index + 1);
    }
    eprintln!("  0) Cancel");

    let mut stdin = std::io::stdin().lock();
    loop {
        eprint!("Credential: ");
        if std::io::stderr().flush().is_err() {
            return None;
        }
        let mut input = String::new();
        match stdin.read_line(&mut input) {
            Ok(0) | Err(_) => return None,
            Ok(_) => match parse_result_selection(&input, users.len()) {
                Ok(selection) => return selection,
                Err(()) => eprintln!("Enter 1-{} or 0 to cancel.", users.len()),
            },
        }
    }
}

fn status_loop(status: Receiver<StatusUpdate>, pin_cache: Option<PinCache>) {
    while let Ok(update) = status.recv() {
        match update {
            StatusUpdate::PresenceRequired => {
                eprintln!("Touch or confirm on your FIDO2 security key...");
            }
            StatusUpdate::SelectDeviceNotice => {
                eprintln!("Multiple FIDO2 security keys found; touch the one to use...");
            }
            StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                send_pin(sender, pin_cache.as_ref(), true)
            }
            StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts)) => {
                match attempts {
                    Some(n) => eprintln!("Incorrect FIDO2 PIN ({n} attempts remaining)."),
                    None => eprintln!("Incorrect FIDO2 PIN."),
                }
                send_pin(sender, pin_cache.as_ref(), false);
            }
            StatusUpdate::PinUvError(StatusPinUv::PinNotSet) => {
                eprintln!(
                    "This control key requires user verification, but the authenticator has \
                     no FIDO2 PIN. Set one with the vendor tool and retry."
                );
            }
            StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked) => {
                eprintln!(
                    "FIDO2 PIN authentication is temporarily blocked; unplug and reconnect \
                     the authenticator."
                );
            }
            StatusUpdate::PinUvError(StatusPinUv::PinBlocked) => {
                eprintln!(
                    "The FIDO2 PIN is blocked. The authenticator's FIDO2 application must be \
                     reset, which erases its FIDO2 credentials."
                );
            }
            StatusUpdate::PinUvError(StatusPinUv::InvalidUv(attempts)) => match attempts {
                Some(n) => {
                    eprintln!("FIDO2 user verification failed ({n} attempts remaining).")
                }
                None => eprintln!("FIDO2 user verification failed; try again."),
            },
            StatusUpdate::PinUvError(StatusPinUv::UvBlocked) => {
                eprintln!("FIDO2 user verification is blocked on this authenticator.");
            }
            StatusUpdate::PinUvError(StatusPinUv::PinIsTooShort) => {
                eprintln!("The supplied FIDO2 PIN is too short.");
            }
            StatusUpdate::PinUvError(StatusPinUv::PinIsTooLong(len)) => {
                eprintln!("The supplied FIDO2 PIN is too long ({len} bytes).");
            }
            StatusUpdate::SelectResultNotice(sender, users) => {
                let _ = sender.send(prompt_result_selection(&users));
            }
            StatusUpdate::InteractiveManagement(_) => {
                eprintln!("Ignoring unexpected interactive FIDO2 management status.");
            }
        }
    }
}

fn cancel_and_join_status_worker<E>(
    cancel: impl FnOnce() -> Result<(), E>,
    status_thread: thread::JoinHandle<()>,
) {
    if cancel().is_err() {
        // Do not join when cancellation fails: the authenticator service may
        // still own a status sender, which would recreate the deadlock this
        // cleanup is intended to prevent. Dropping the service will close it.
        return;
    }
    let _ = status_thread.join();
}

fn run_operation<T, F>(
    context: &str,
    pin_cache: Option<PinCache>,
    service: &mut AuthenticatorService,
    start: F,
) -> Result<T, CliError>
where
    T: Send + 'static,
    F: FnOnce(
        &mut AuthenticatorService,
        Sender<StatusUpdate>,
        StateCallback<authenticator::Result<T>>,
    ) -> authenticator::Result<()>,
{
    let (status_tx, status_rx) = channel();
    let status_thread = thread::spawn(move || status_loop(status_rx, pin_cache));
    let (result_tx, result_rx) = channel();
    let callback = StateCallback::new(Box::new(move |result| {
        let _ = result_tx.send(result);
    }));

    let started = start(service, status_tx.clone(), callback);
    drop(status_tx);
    if let Err(e) = started {
        cancel_and_join_status_worker(|| service.cancel(), status_thread);
        return Err(CliError::Other(format!("{context}: {e}")));
    }

    let result = result_rx.recv();
    cancel_and_join_status_worker(|| service.cancel(), status_thread);

    let result =
        result.map_err(|e| CliError::Other(format!("{context}: result channel closed: {e}")))?;
    result.map_err(|e| CliError::Other(format!("{context}: {e}")))
}

fn validate_credential_id(credential_id: &[u8]) -> Result<(), CliError> {
    if credential_id.is_empty() || credential_id.len() > 1023 {
        return Err(CliError::Other(format!(
            "authenticator returned an invalid credential ID length ({})",
            credential_id.len()
        )));
    }
    Ok(())
}

fn public_key_from_cose(cose: &COSEKey) -> Result<[u8; 65], CliError> {
    if cose.alg != COSEAlgorithm::ES256 {
        return Err(CliError::Other(
            "authenticator returned a credential that is not ES256".into(),
        ));
    }
    let ec = match &cose.key {
        COSEKeyType::EC2(ec) if ec.curve == Curve::SECP256R1 => ec,
        _ => {
            return Err(CliError::Other(
                "authenticator returned a non-P-256 credential".into(),
            ));
        }
    };
    if ec.x.len() != 32 || ec.y.len() != 32 {
        return Err(CliError::Other(format!(
            "authenticator returned malformed P-256 coordinates (x={}, y={})",
            ec.x.len(),
            ec.y.len()
        )));
    }
    let mut public_key = [0u8; 65];
    public_key[0] = 0x04;
    public_key[1..33].copy_from_slice(&ec.x);
    public_key[33..].copy_from_slice(&ec.y);
    p256::PublicKey::from_sec1_bytes(&public_key).map_err(|e| {
        CliError::Other(format!(
            "authenticator returned an invalid P-256 public key: {e}"
        ))
    })?;
    Ok(public_key)
}

/// Create a modern, discoverable CTAP2 ES256 credential on an
/// attached hardware authenticator.
pub fn register_fido2_credential(name: &str) -> Result<RegisteredFido2Credential, CliError> {
    let mut service = new_service()?;
    preflight_recoverable_profile(&mut service)?;
    let mut user_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut user_id);

    let args = RegisterArgs {
        // Registration attestation is neither retained nor verified
        // later, so this is intentionally a fixed, domain-separated
        // context rather than a security challenge. Assertion hashes
        // remain message- and credential-bound.
        client_data_hash: Sha256::digest(FIDO2_REGISTRATION_CLIENT_DATA_CONTEXT).into(),
        relying_party: RelyingParty {
            id: FIDO2_RP_ID.into(),
            name: Some("Enclavia control key".into()),
        },
        origin: FIDO2_ORIGIN.into(),
        user: PublicKeyCredentialUserEntity {
            id: user_id.to_vec(),
            name: Some(name.into()),
            display_name: Some(format!("Enclavia control key {name}")),
        },
        pub_cred_params: vec![PublicKeyCredentialParameters {
            alg: COSEAlgorithm::ES256,
        }],
        exclude_list: Vec::new(),
        user_verification_req: UserVerificationRequirement::Required,
        resident_key_req: ResidentKeyRequirement::Required,
        extensions: AuthenticationExtensionsClientInputs {
            // Require a discoverable credential and protect it from
            // allow-list-free use without user verification.
            cred_props: Some(true),
            credential_protection_policy: Some(
                CredentialProtectionPolicy::UserVerificationRequired,
            ),
            enforce_credential_protection_policy: Some(true),
            ..AuthenticationExtensionsClientInputs::default()
        },
        pin: None,
        // authenticator-rs 0.5 exposes no user-presence option on
        // RegisterArgs. CTAP2 makeCredential normally requires UP;
        // because the API cannot express that requirement, we also
        // enforce the returned UP flag below. A non-conforming token
        // could therefore create a credential which this CLI
        // immediately rejects.
        // Modern FIDO2 only: never silently downgrade to U2F/CTAP1.
        use_ctap1_fallback: false,
    };

    eprintln!(
        "Creating a discoverable CTAP2 ES256 control credential (PIN/user verification and \
         touch required)."
    );
    let result = run_operation(
        "creating FIDO2 credential",
        None,
        &mut service,
        |service, status, callback| service.register(OPERATION_TIMEOUT_MS, args, status, callback),
    )?;

    if !result.extensions.cred_props.is_some_and(|props| props.rk) {
        return Err(CliError::Other(
            "authenticator did not confirm creation of a discoverable credential".into(),
        ));
    }
    let auth_data = result.att_obj.auth_data;
    if auth_data.rp_id_hash != RelyingParty::from(FIDO2_RP_ID).hash() {
        return Err(CliError::Other(
            "authenticator returned credential data for the wrong RP ID".into(),
        ));
    }
    if !auth_data
        .flags
        .contains(AuthenticatorDataFlags::USER_PRESENT)
    {
        return Err(CliError::Other(
            "authenticator did not prove user presence during credential creation".into(),
        ));
    }
    if !auth_data
        .flags
        .contains(AuthenticatorDataFlags::USER_VERIFIED)
    {
        return Err(CliError::Other(
            "authenticator did not prove user verification during credential creation".into(),
        ));
    }
    // authenticator-rs 0.5 names the WebAuthn BE/BS bits
    // RESERVED_3/RESERVED_4. Reject BE even at registration for an
    // early diagnostic; the protocol verifier repeats this policy
    // on every assertion because that is the security boundary.
    const BACKUP_ELIGIBLE: u8 = 0x08;
    const BACKUP_STATE: u8 = 0x10;
    let flags = auth_data.flags.bits();
    if flags & BACKUP_STATE != 0 && flags & BACKUP_ELIGIBLE == 0 {
        return Err(CliError::Other(
            "authenticator returned an invalid backup-state flag combination".into(),
        ));
    }
    if flags & BACKUP_ELIGIBLE != 0 {
        return Err(CliError::Other(
            "authenticator created a backup-eligible credential, which Enclavia rejects \
             because it may be synced or exported; the rejected credential may still occupy \
             space on the authenticator"
                .into(),
        ));
    }

    let credential = auth_data.credential_data.ok_or_else(|| {
        CliError::Other("authenticator returned no attested credential data".into())
    })?;
    validate_credential_id(&credential.credential_id)?;
    let public_key = public_key_from_cose(&credential.credential_public_key)?;

    Ok(RegisteredFido2Credential {
        credential_id: credential.credential_id,
        public_key,
        aaguid: credential.aaguid.0,
    })
}

struct Fido2CredentialInventory {
    aaguid: [u8; 16],
    credentials: CredentialList,
}

fn finish_credential_management(
    request: Option<&Sender<InteractiveRequest>>,
    inventory: &Sender<Result<Fido2CredentialInventory, CliError>>,
    result: Result<Fido2CredentialInventory, CliError>,
) {
    let _ = inventory.send(result);
    if let Some(request) = request {
        let _ = request.send(InteractiveRequest::Quit);
    }
}

fn credential_management_status_loop(
    status: Receiver<StatusUpdate>,
    inventory: Sender<Result<Fido2CredentialInventory, CliError>>,
) {
    let mut request = None;
    let mut aaguid = None;
    let mut finished = false;

    while let Ok(update) = status.recv() {
        match update {
            StatusUpdate::PresenceRequired => {
                eprintln!("Touch or confirm on your FIDO2 security key...");
            }
            StatusUpdate::SelectDeviceNotice => {
                eprintln!("Multiple FIDO2 security keys found; touch the one to inspect...");
            }
            StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                send_pin(sender, None, true)
            }
            StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts)) => {
                match attempts {
                    Some(n) => eprintln!("Incorrect FIDO2 PIN ({n} attempts remaining)."),
                    None => eprintln!("Incorrect FIDO2 PIN."),
                }
                send_pin(sender, None, false);
            }
            StatusUpdate::PinUvError(StatusPinUv::PinNotSet) => {
                eprintln!(
                    "FIDO2 credential recovery requires user verification, but the \
                     authenticator has no FIDO2 PIN."
                );
            }
            StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked) => {
                eprintln!(
                    "FIDO2 PIN authentication is temporarily blocked; unplug and reconnect \
                     the authenticator."
                );
            }
            StatusUpdate::PinUvError(StatusPinUv::PinBlocked) => {
                eprintln!(
                    "The FIDO2 PIN is blocked. Resetting the authenticator would erase its \
                     FIDO2 credentials."
                );
            }
            StatusUpdate::PinUvError(StatusPinUv::InvalidUv(attempts)) => match attempts {
                Some(n) => {
                    eprintln!("FIDO2 user verification failed ({n} attempts remaining).")
                }
                None => eprintln!("FIDO2 user verification failed; try again."),
            },
            StatusUpdate::PinUvError(StatusPinUv::UvBlocked) => {
                eprintln!("FIDO2 user verification is blocked on this authenticator.");
            }
            StatusUpdate::PinUvError(StatusPinUv::PinIsTooShort) => {
                eprintln!("The supplied FIDO2 PIN is too short.");
            }
            StatusUpdate::PinUvError(StatusPinUv::PinIsTooLong(len)) => {
                eprintln!("The supplied FIDO2 PIN is too long ({len} bytes).");
            }
            StatusUpdate::InteractiveManagement(InteractiveUpdate::StartManagement((
                management,
                info,
            ))) => {
                request = Some(management);
                let Some(info) = info else {
                    finish_credential_management(
                        request.as_ref(),
                        &inventory,
                        Err(CliError::Other(
                            "selected authenticator does not support CTAP2".into(),
                        )),
                    );
                    finished = true;
                    continue;
                };
                if let Err(error) = validate_recoverable_profile(&info) {
                    finish_credential_management(request.as_ref(), &inventory, Err(error));
                    finished = true;
                    continue;
                }
                aaguid = Some(info.aaguid.0);
                if request
                    .as_ref()
                    .expect("management request sender was just stored")
                    .send(InteractiveRequest::CredentialManagement(
                        CredManagementCmd::GetCredentials,
                        None,
                    ))
                    .is_err()
                {
                    finish_credential_management(
                        request.as_ref(),
                        &inventory,
                        Err(CliError::Other(
                            "FIDO2 credential-management operation ended before enumeration".into(),
                        )),
                    );
                    finished = true;
                }
            }
            StatusUpdate::InteractiveManagement(InteractiveUpdate::CredentialManagementUpdate(
                (CredentialManagementResult::CredentialList(credentials), _),
            )) if !finished => {
                let result = aaguid
                    .map(|aaguid| Fido2CredentialInventory {
                        aaguid,
                        credentials,
                    })
                    .ok_or_else(|| {
                        CliError::Other(
                            "authenticator returned credentials before device information".into(),
                        )
                    });
                finish_credential_management(request.as_ref(), &inventory, result);
                finished = true;
            }
            StatusUpdate::InteractiveManagement(_) if !finished => {
                finish_credential_management(
                    request.as_ref(),
                    &inventory,
                    Err(CliError::Other(
                        "authenticator returned an unexpected credential-management result".into(),
                    )),
                );
                finished = true;
            }
            StatusUpdate::SelectResultNotice(sender, _) => {
                let _ = sender.send(None);
            }
            _ => {}
        }
    }
}

fn select_recovered_fido2_credential(
    name: &str,
    inventory: Fido2CredentialInventory,
) -> Result<RecoveredFido2Credential, CliError> {
    let expected_rp_hash = RelyingParty::from(FIDO2_RP_ID).hash();
    let mut candidates = Vec::new();
    let mut available_names = Vec::new();

    for rp in inventory.credentials.credential_list {
        if rp.rp.id != FIDO2_RP_ID || rp.rp_id_hash != expected_rp_hash {
            continue;
        }
        for credential in rp.credentials {
            if let Some(credential_name) = credential.user.name.as_deref() {
                available_names.push(credential_name.to_string());
                if credential_name == name {
                    candidates.push(credential);
                }
            }
        }
    }

    available_names.sort();
    available_names.dedup();
    if candidates.is_empty() {
        let available = if available_names.is_empty() {
            "none".to_string()
        } else {
            available_names
                .iter()
                .map(|name| format!("{name:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        return Err(CliError::Other(format!(
            "no discoverable Enclavia FIDO2 credential named {name:?} was found on the \
             selected authenticator (available names: {available})"
        )));
    }
    if candidates.len() > 1 {
        return Err(CliError::Other(format!(
            "the selected authenticator contains multiple Enclavia FIDO2 credentials named \
             {name:?}; rename or remove the duplicate before importing"
        )));
    }

    let credential = candidates.pop().expect("one candidate checked above");
    if credential.cred_protect != CredentialProtectionPolicy::UserVerificationRequired as u64 {
        return Err(CliError::Other(format!(
            "FIDO2 credential {name:?} does not require user verification and is not a \
             supported Enclavia control credential"
        )));
    }
    validate_credential_id(&credential.credential_id.id)?;
    let public_key = public_key_from_cose(&credential.public_key)?;

    Ok(RecoveredFido2Credential {
        credential_id: credential.credential_id.id,
        public_key,
        aaguid: inventory.aaguid,
    })
}

/// Recover one Enclavia credential's public metadata from a modern
/// authenticator. The credential must be discoverable, scoped to
/// Enclavia's RP ID, named exactly `name`, protected by user
/// verification, and enumerable through CTAP2 credential management.
pub fn recover_fido2_credential(name: &str) -> Result<RecoveredFido2Credential, CliError> {
    let mut service = new_service()?;
    let (status_tx, status_rx) = channel();
    let (inventory_tx, inventory_rx) = channel();
    let status_thread =
        thread::spawn(move || credential_management_status_loop(status_rx, inventory_tx));
    let (result_tx, result_rx) = channel();
    let callback = StateCallback::new(Box::new(move |result| {
        let _ = result_tx.send(result);
    }));

    eprintln!(
        "Inspecting discoverable FIDO2 credentials for RP {FIDO2_RP_ID:?} (touch and user \
         verification required)."
    );
    let started = service.manage(OPERATION_TIMEOUT_MS, status_tx.clone(), callback);
    drop(status_tx);
    if let Err(error) = started {
        let _ = service.cancel();
        let _ = status_thread.join();
        return Err(CliError::Other(format!(
            "enumerating FIDO2 credentials: {error}"
        )));
    }

    let management = result_rx.recv();
    let _ = service.cancel();
    let _ = status_thread.join();
    management
        .map_err(|error| {
            CliError::Other(format!(
                "enumerating FIDO2 credentials: result channel closed: {error}"
            ))
        })?
        .map_err(|error| CliError::Other(format!("enumerating FIDO2 credentials: {error}")))?;
    let inventory = inventory_rx.recv().map_err(|error| {
        CliError::Other(format!(
            "enumerating FIDO2 credentials: no credential inventory returned: {error}"
        ))
    })??;
    select_recovered_fido2_credential(name, inventory)
}

/// Signing handle for one discoverable FIDO2 credential. Routine
/// signing still supplies its exact credential ID to avoid ambiguous
/// account selection; discovery is used only for index recovery.
pub struct Fido2Signer {
    credential_id: Vec<u8>,
    public_key: [u8; 65],
    pin: PinCache,
    last_sign_count: Mutex<Option<u32>>,
}

impl Fido2Signer {
    pub fn new(credential_id: Vec<u8>, public_key: [u8; 65]) -> Result<Self, CliError> {
        if credential_id.is_empty() || credential_id.len() > 1023 {
            return Err(CliError::Other(format!(
                "FIDO2 credential ID must contain 1-1023 bytes, got {}",
                credential_id.len()
            )));
        }
        Ok(Self {
            credential_id,
            public_key,
            pin: Arc::new(Mutex::new(None)),
            last_sign_count: Mutex::new(None),
        })
    }
}

impl ControlSigner for Fido2Signer {
    fn public_key(&self) -> [u8; 65] {
        self.public_key
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CliError> {
        let mut service = new_service()?;
        let args = SignArgs {
            client_data_hash: fido2_client_data_hash(msg, &self.credential_id),
            origin: FIDO2_ORIGIN.into(),
            relying_party_id: FIDO2_RP_ID.into(),
            allow_list: vec![PublicKeyCredentialDescriptor {
                id: self.credential_id.clone(),
                transports: vec![Transport::USB],
            }],
            user_verification_req: UserVerificationRequirement::Required,
            user_presence_req: true,
            extensions: AuthenticationExtensionsClientInputs::default(),
            // Reuse the PIN between the inner and envelope
            // assertions in one CLI process, matching the PIV
            // backend's prompt-once behavior.
            pin: self.pin.lock().expect("poisoned FIDO2 PIN cache").clone(),
            // Modern FIDO2 only: never silently downgrade to U2F/CTAP1.
            use_ctap1_fallback: false,
        };

        let result = run_operation(
            "requesting FIDO2 assertion",
            Some(Arc::clone(&self.pin)),
            &mut service,
            |service, status, callback| service.sign(OPERATION_TIMEOUT_MS, args, status, callback),
        )?;
        if result
            .assertion
            .credentials
            .as_ref()
            .is_some_and(|selected| selected.id != self.credential_id)
        {
            return Err(CliError::Other(
                "authenticator returned an assertion for a different credential".into(),
            ));
        }

        let proof = Fido2Assertion {
            credential_id: self.credential_id.clone(),
            authenticator_data: result.assertion.auth_data.to_vec(),
            signature: result.assertion.signature,
        }
        .encode();

        // Fail locally before submitting if the authenticator
        // response does not satisfy the enclave's exact verifier.
        let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.public_key)
            .map_err(|e| CliError::Other(format!("invalid stored FIDO2 public key: {e}")))?;
        let verified = verify_control_proof(&verifying_key, msg, &proof)
            .map_err(|e| CliError::Other(format!("invalid FIDO2 assertion: {e}")))?;
        let current = verified
            .sign_count
            .expect("FIDO2 verification always returns a signature counter");
        let mut previous = self
            .last_sign_count
            .lock()
            .expect("poisoned FIDO2 signature-counter state");
        if let Some(previous) = *previous {
            check_fido2_sign_count(previous, current)
                .map_err(|e| CliError::Other(format!("invalid FIDO2 assertion: {e}")))?;
        }
        *previous = Some(current);
        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use authenticator::crypto::{COSEEC2Key, COSEKey};
    use authenticator::ctap2::commands::credential_management::{
        CredentialListEntry, CredentialRpListEntry,
    };
    use authenticator::ctap2::commands::get_info::{AuthenticatorOptions, AuthenticatorVersion};

    use super::*;

    fn supported_authenticator_info() -> AuthenticatorInfo {
        AuthenticatorInfo {
            versions: vec![AuthenticatorVersion::FIDO_2_1],
            extensions: vec!["credProtect".into()],
            options: AuthenticatorOptions {
                resident_key: true,
                client_pin: Some(true),
                cred_mgmt: Some(true),
                ..AuthenticatorOptions::default()
            },
            algorithms: Some(vec![PublicKeyCredentialParameters {
                alg: COSEAlgorithm::ES256,
            }]),
            ..AuthenticatorInfo::default()
        }
    }

    fn inventory(entries: &[(&str, u8, u64)]) -> Fido2CredentialInventory {
        let credentials = entries
            .iter()
            .map(|(name, seed, cred_protect)| {
                use p256::elliptic_curve::sec1::ToEncodedPoint as _;

                let secret = p256::SecretKey::from_bytes(&[*seed; 32].into()).unwrap();
                let point = secret.public_key().to_encoded_point(false);
                CredentialListEntry {
                    user: PublicKeyCredentialUserEntity {
                        id: vec![*seed; 32],
                        name: Some((*name).into()),
                        display_name: Some(format!("Enclavia control key {name}")),
                    },
                    credential_id: PublicKeyCredentialDescriptor {
                        id: vec![*seed; 32],
                        transports: vec![Transport::USB],
                    },
                    public_key: COSEKey {
                        alg: COSEAlgorithm::ES256,
                        key: COSEKeyType::EC2(
                            COSEEC2Key::from_sec1_uncompressed(Curve::SECP256R1, point.as_bytes())
                                .unwrap(),
                        ),
                    },
                    cred_protect: *cred_protect,
                    large_blob_key: None,
                }
            })
            .collect();
        let rp = RelyingParty::from(FIDO2_RP_ID);
        Fido2CredentialInventory {
            aaguid: [0xA5; 16],
            credentials: CredentialList {
                existing_resident_credentials_count: entries.len() as u64,
                max_possible_remaining_resident_credentials_count: 10,
                credential_list: vec![CredentialRpListEntry {
                    rp: rp.clone(),
                    rp_id_hash: rp.hash(),
                    credentials,
                }],
            },
        }
    }

    #[test]
    fn result_selection_is_explicit_and_one_based() {
        assert_eq!(parse_result_selection("1\n", 3), Ok(Some(0)));
        assert_eq!(parse_result_selection("3", 3), Ok(Some(2)));
        assert_eq!(parse_result_selection("0", 3), Ok(None));
        assert_eq!(parse_result_selection("4", 3), Err(()));
        assert_eq!(parse_result_selection("not a number", 3), Err(()));
    }

    #[test]
    fn operation_cleanup_cancels_before_joining_status_worker() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (release_tx, release_rx) = channel();
        let worker_events = Arc::clone(&events);
        let status_thread = thread::spawn(move || {
            let event = match release_rx.recv_timeout(std::time::Duration::from_secs(1)) {
                Ok(()) => "status worker exited",
                Err(_) => "status worker timed out",
            };
            worker_events.lock().unwrap().push(event);
        });

        let cancel_events = Arc::clone(&events);
        cancel_and_join_status_worker(
            move || {
                cancel_events.lock().unwrap().push("transaction cancelled");
                release_tx
                    .send(())
                    .map_err(|_| "status worker stopped before cancellation")?;
                Ok::<(), &'static str>(())
            },
            status_thread,
        );

        assert_eq!(
            *events.lock().unwrap(),
            vec!["transaction cancelled", "status worker exited"]
        );
    }

    #[test]
    fn recoverable_profile_accepts_client_pin_and_standard_credential_management() {
        validate_recoverable_profile(&supported_authenticator_info()).unwrap();
    }

    #[test]
    fn recoverable_profile_accepts_built_in_uv_and_legacy_credential_management() {
        let mut info = supported_authenticator_info();
        info.options.client_pin = None;
        info.options.user_verification = Some(true);
        info.options.cred_mgmt = None;
        info.options.credential_mgmt_preview = Some(true);

        validate_recoverable_profile(&info).unwrap();
    }

    #[test]
    fn recoverable_profile_reports_trezor_capability_gap() {
        let info = AuthenticatorInfo {
            versions: vec![AuthenticatorVersion::U2F_V2, AuthenticatorVersion::FIDO_2_0],
            extensions: vec!["hmac-secret".into()],
            options: AuthenticatorOptions {
                resident_key: true,
                user_verification: Some(true),
                ..AuthenticatorOptions::default()
            },
            ..AuthenticatorInfo::default()
        };

        let error = validate_recoverable_profile(&info).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("FIDO_2_0"));
        assert!(message.contains("credProtect=UserVerificationRequired"));
        assert!(message.contains("CTAP2 credential management"));
        assert!(!message.contains("configured user verification (`clientPin`"));
    }

    #[test]
    fn recoverable_profile_reports_unconfigured_uv_and_missing_es256() {
        let mut info = supported_authenticator_info();
        info.options.client_pin = Some(false);
        info.algorithms = Some(vec![PublicKeyCredentialParameters {
            alg: COSEAlgorithm::EDDSA,
        }]);

        let missing = missing_recoverable_profile_capabilities(&info);
        assert_eq!(
            missing,
            vec![
                "configured user verification (`clientPin` or built-in `uv`)",
                "ES256 credential creation",
            ]
        );
    }

    #[test]
    fn recoverable_profile_explains_how_to_configure_fido2_pin() {
        let mut info = supported_authenticator_info();
        info.options.client_pin = Some(false);

        let error = validate_recoverable_profile(&info).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("does not have a FIDO2 PIN configured"));
        assert!(message.contains("ykman fido access change-pin"));
        assert!(message.contains("FIDO2 PIN is separate from the PIV PIN"));
        assert!(!message.contains("does not support Enclavia"));
    }

    #[test]
    fn recovery_selects_named_uv_protected_credential() {
        let recovered = select_recovered_fido2_credential(
            "prod",
            inventory(&[
                ("other", 0x11, 3),
                (
                    "prod",
                    0x22,
                    CredentialProtectionPolicy::UserVerificationRequired as u64,
                ),
            ]),
        )
        .unwrap();
        assert_eq!(recovered.credential_id, vec![0x22; 32]);
        assert_eq!(recovered.aaguid, [0xA5; 16]);
        assert_eq!(recovered.public_key[0], 0x04);
    }

    #[test]
    fn recovery_reports_available_names() {
        let error = select_recovered_fido2_credential("missing", inventory(&[("prod", 0x22, 3)]))
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("\"missing\""));
        assert!(message.contains("\"prod\""));
    }

    #[test]
    fn recovery_rejects_credential_without_required_cred_protect() {
        let error =
            select_recovered_fido2_credential("prod", inventory(&[("prod", 0x22, 2)])).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not require user verification")
        );
    }

    #[test]
    fn recovery_ignores_mismatched_rp_entity() {
        let mut inventory = inventory(&[("prod", 0x22, 3)]);
        inventory.credentials.credential_list[0].rp.id = "lookalike.example".into();

        let error = select_recovered_fido2_credential("prod", inventory).unwrap_err();
        assert!(error.to_string().contains("available names: none"));
    }
}
