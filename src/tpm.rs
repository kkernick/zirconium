//! This file contains the TPM related functions.
//!
//! Zirconium installs an AES wrapping key within the TPM, which is then used
//! to encrypt/decrypt secrets. The TPM is also used as a HRNG generator

use crate::config::Config;
use bstr::{BStr, BString};
use openssl::sha::sha256;
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    constants::SessionType,
    handles::{KeyHandle, ObjectHandle, PcrHandle, PersistentTpmHandle, SessionHandle, TpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode},
        dynamic_handles::Persistent,
        resource_handles::{Hierarchy, Provision},
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Digest, DigestValues, InitialValue, MaxBuffer, PcrSelectionList, PcrSelectionListBuilder,
        PcrSlot, PublicBuilder, SensitiveData, SymmetricCipherParameters, SymmetricDefinition,
        SymmetricDefinitionObject,
    },
    Context,
    Error::{self, WrapperError},
    Result, WrapperErrorKind,
};

/// Generate random bytes from the TPM
///
/// ## Errors
///
/// If we cannot get bytes from the TPM
pub fn generate_bytes(context: &mut Context, bytes: u16) -> Result<SensitiveData> {
    SensitiveData::try_from(context.get_random(bytes as usize)?.value())
}

/// Get the slot for a PCR value
///
/// ## Errors
///
/// If the PCR value is invalid
pub const fn get_slot(pcr: u8) -> Result<PcrSlot> {
    match pcr {
        0 => Ok(PcrSlot::Slot0),
        1 => Ok(PcrSlot::Slot1),
        2 => Ok(PcrSlot::Slot2),
        3 => Ok(PcrSlot::Slot3),
        4 => Ok(PcrSlot::Slot4),
        5 => Ok(PcrSlot::Slot5),
        6 => Ok(PcrSlot::Slot6),
        7 => Ok(PcrSlot::Slot7),
        8 => Ok(PcrSlot::Slot8),
        9 => Ok(PcrSlot::Slot9),
        10 => Ok(PcrSlot::Slot10),
        11 => Ok(PcrSlot::Slot11),
        12 => Ok(PcrSlot::Slot12),
        13 => Ok(PcrSlot::Slot13),
        14 => Ok(PcrSlot::Slot14),
        15 => Ok(PcrSlot::Slot15),
        16 => Ok(PcrSlot::Slot16),
        17 => Ok(PcrSlot::Slot17),
        18 => Ok(PcrSlot::Slot18),
        19 => Ok(PcrSlot::Slot19),
        20 => Ok(PcrSlot::Slot20),
        21 => Ok(PcrSlot::Slot21),
        22 => Ok(PcrSlot::Slot22),
        23 => Ok(PcrSlot::Slot23),
        _ => Err(WrapperError(WrapperErrorKind::InvalidParam)),
    }
}

/// Get the Handle for a PCR value
///
/// ## Errors
///
/// If the PCR value is invalid
pub const fn get_handle(pcr: u8) -> Result<PcrHandle> {
    match pcr {
        0 => Ok(PcrHandle::Pcr0),
        1 => Ok(PcrHandle::Pcr1),
        2 => Ok(PcrHandle::Pcr2),
        3 => Ok(PcrHandle::Pcr3),
        4 => Ok(PcrHandle::Pcr4),
        5 => Ok(PcrHandle::Pcr5),
        6 => Ok(PcrHandle::Pcr6),
        7 => Ok(PcrHandle::Pcr7),
        8 => Ok(PcrHandle::Pcr8),
        9 => Ok(PcrHandle::Pcr9),
        10 => Ok(PcrHandle::Pcr10),
        11 => Ok(PcrHandle::Pcr11),
        12 => Ok(PcrHandle::Pcr12),
        13 => Ok(PcrHandle::Pcr13),
        14 => Ok(PcrHandle::Pcr14),
        15 => Ok(PcrHandle::Pcr15),
        16 => Ok(PcrHandle::Pcr16),
        17 => Ok(PcrHandle::Pcr17),
        18 => Ok(PcrHandle::Pcr18),
        19 => Ok(PcrHandle::Pcr19),
        20 => Ok(PcrHandle::Pcr20),
        21 => Ok(PcrHandle::Pcr21),
        22 => Ok(PcrHandle::Pcr22),
        23 => Ok(PcrHandle::Pcr23),
        _ => Err(WrapperError(WrapperErrorKind::InvalidParam)),
    }
}

/// Get a `SelectionList` binding PCRs
/// Get a `SelectionList` for the specified PCR indices.
///
/// ## Errors
///
/// If any of the PCR values are invalid
pub fn pcr_selection(pcrs: &[u8]) -> Result<PcrSelectionList> {
    let slots: Vec<PcrSlot> = pcrs
        .iter()
        .map(|pcr| get_slot(*pcr))
        .collect::<Result<Vec<_>>>()?;

    if slots.is_empty() {
        return Err(WrapperError(WrapperErrorKind::InvalidParam));
    }

    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &slots)
        .build()
}

/// Check if a given address is occupied already
///
/// ## Errors
///
/// If we cannot get a handle on the TPM
pub fn occupied(ctx: &mut Context, address: u32) -> Result<bool> {
    let persistent = PersistentTpmHandle::new(address)?;

    match ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent)) {
        Ok(mut handle) => {
            ctx.tr_close(&mut handle)?;
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

/// Compute the policy digest for the current PCR 0 and 7 values.
/// Use a trial session: it calculates the policy without authorizing
/// an actual unseal operation.
///
/// ## Errors
///
/// If the PCR list in invalid, or acquire a Policy Sessions from the TPM, or use the Session.
pub fn current_pcr_policy(ctx: &mut Context, config: &Config) -> Result<Digest> {
    let selection = pcr_selection(&config.pcrs)?;
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::Null,
            HashingAlgorithm::Sha256,
        )?
        .ok_or(Error::WrapperError(WrapperErrorKind::InvalidParam))?;

    let policy_session = PolicySession::try_from(session)?;
    ctx.policy_pcr(policy_session, Digest::default(), selection)?;

    let digest = ctx.policy_get_digest(policy_session)?;
    ctx.flush_context(SessionHandle::from(policy_session).into())?;
    Ok(digest)
}

/// Enroll the wrapping key used for unsealing operations
///
/// ## Errors
///
/// If we cannot acquire/use the TPM
pub fn enroll_wrapping_key(ctx: &mut Context, config: &Config, address: u32) -> Result<()> {
    let persistent = PersistentTpmHandle::new(address)?;

    if occupied(ctx, address)? {
        // Remove the existing persistent key.
        let existing = ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent))?;

        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(
                Provision::Owner,
                existing,
                Persistent::Persistent(persistent),
            )
        })?;
    }

    // Create a fresh TPM-generated AES wrapping key.
    let policy_digest = current_pcr_policy(ctx, config)?;

    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(false)
        .with_sign_encrypt(true)
        .with_decrypt(true)
        .with_restricted(false)
        .build()?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_auth_policy(policy_digest)
        .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::AES_256_CFB,
        ))
        .with_symmetric_cipher_unique_identifier(Digest::default())
        .build()?;

    let primary = ctx.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
    })?;

    let persist_result = ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
        ctx.evict_control(
            Provision::Owner,
            ObjectHandle::from(primary.key_handle),
            Persistent::Persistent(persistent),
        )
    });

    let cleanup_result = ctx.flush_context(primary.key_handle.into());

    persist_result?;
    cleanup_result?;

    Ok(())
}

/// Get a handle to the wrapping key
fn get_key(ctx: &mut Context, address: u32) -> Result<KeyHandle> {
    let persistent = PersistentTpmHandle::new(address)?;
    let object = ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent))?;
    Ok(KeyHandle::from(object))
}

/// Begin a Policy Session
fn get_session(ctx: &mut Context, config: &Config) -> Result<AuthSession> {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::Null,
            HashingAlgorithm::Sha256,
        )?
        .ok_or(Error::WrapperError(WrapperErrorKind::InvalidParam))?;

    let policy_session = PolicySession::try_from(session)?;

    ctx.policy_pcr(
        policy_session,
        Digest::default(),
        pcr_selection(&config.pcrs)?,
    )?;

    Ok(session)
}

/// Encrypt some text with the wrapping key
///
/// ## Errors
///
/// If we cannot acquire/use the TPM
pub fn encrypt(
    ctx: &mut Context,
    config: &Config,
    address: u32,
    plaintext: &SensitiveData,
    iv: &BStr,
) -> Result<BString> {
    let key = get_key(ctx, address)?;
    let session = get_session(ctx, config)?;

    let input = MaxBuffer::try_from(plaintext.to_vec())?;
    let initial_value = InitialValue::try_from(iv.to_vec())?;

    let result = ctx.execute_with_session(Some(session), |ctx| {
        ctx.encrypt_decrypt_2(key, false, SymmetricMode::Cfb, input, initial_value)
    });

    // Session cleanup should also be handled if the command fails.
    let cleanup = ctx.flush_context(ObjectHandle::from(SessionHandle::from(session)));
    let (ciphertext, _iv_out) = result?;
    cleanup?;
    Ok(ciphertext.value().into())
}

/// Decrypt some ciphertext with the wrapping key
///
/// ## Errors
///
/// If we cannot acquire/use the TPM
pub fn decrypt(
    ctx: &mut Context,
    config: &Config,
    address: u32,
    ciphertext: &BStr,
    iv: &BStr,
) -> Result<SensitiveData> {
    let key = get_key(ctx, address)?;
    let session = get_session(ctx, config)?;

    let input = MaxBuffer::try_from(ciphertext.to_vec())?;
    let initial_value = InitialValue::try_from(iv.to_vec())?;

    let result = ctx.execute_with_session(Some(session), |ctx| {
        ctx.encrypt_decrypt_2(key, true, SymmetricMode::Cfb, input, initial_value)
    });

    let cleanup = ctx.flush_context(ObjectHandle::from(SessionHandle::from(session)));
    let (plaintext, _iv_out) = result?;
    cleanup?;

    SensitiveData::try_from(plaintext.value())
}

/// Remove the persistent wrapping key.
///
/// ## Errors
///
/// If we cannot acquire/use the TPM
pub fn evict(ctx: &mut Context, address: u32) -> Result<bool> {
    let persistent = PersistentTpmHandle::new(address)?;

    let Ok(object) = ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent)) else {
        return Ok(false);
    };

    ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
        ctx.evict_control(Provision::Owner, object, Persistent::Persistent(persistent))
    })?;

    Ok(true)
}

/// Extend configured PCRs with SHA-256 hashes of their current values,
/// invalidating policies bound to the previous measurements.
///
/// Returns a SHA-256 digest representing the original PCR measurements.
///
/// ## Errors
///
/// If we cannot acquire/use the TPM.
pub fn wipe(ctx: &mut Context, config: &Config) -> Result<()> {
    for &pcr in &config.pcrs {
        let slot = get_slot(pcr)?;
        let handle = get_handle(pcr)?;

        let selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[slot])
            .build()?;

        let (_, _, digests) = ctx.pcr_read(selection)?;

        let old_value = digests
            .value()
            .first()
            .ok_or(WrapperError(WrapperErrorKind::InvalidParam))?
            .value();

        let extension = sha256(old_value);

        let digest = Digest::try_from(extension.to_vec())?;

        let mut values = DigestValues::new();
        values.set(HashingAlgorithm::Sha256, digest);

        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.pcr_extend(handle, values)
        })?;
    }
    Ok(())
}
