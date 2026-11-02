#![allow(clippy::missing_docs_in_private_items)]

use crate::tpm;
use bstr::BString;
use openssl::{
    error::ErrorStack,
    kdf::argon2id,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};
use spawn::{HandleError, SpawnError, Spawner, StreamMode};
use thiserror::Error;
use tss_esapi::Context;

/// The salt size.
const SALT_LEN: usize = 16;

/// The nonce size
const NONCE_LEN: usize = 12;

/// Tag length
const TAG_LEN: usize = 16;

/// Pin Errors
#[derive(Debug, Error)]
pub enum Error {
    #[error("OpenSSL operation failed: {0}")]
    OpenSSL(#[from] ErrorStack),

    #[error("TPM operation failed: {0}")]
    Tpm(#[from] tss_esapi::Error),

    #[error("Invalid PIN-sealed blob: {0}")]
    InvalidFormat(&'static str),

    #[error("Failed to spawn process: {0}")]
    Spawn(#[from] SpawnError),

    #[error("Failed to communicate with process: {0}")]
    Handle(#[from] HandleError),
}

/// Ask for the PIN. Verify to make sure the user inputs it correctly
///
/// ## Errors
///
/// If `systemd-ask-password` fails, or we couldn't gather the output
pub fn ask_pin(prompt: &str, verify: bool) -> Result<BString, Error> {
    let ask = |prompt: &str| -> Result<String, Error> {
        let output = Spawner::abs("/usr/bin/systemd-ask-password")
            .args(["-n", prompt])
            .output(StreamMode::Pipe)
            .spawn()?
            .output_all()?;
        Ok(output)
    };

    loop {
        let first = ask(prompt)?;
        if verify {
            let second = ask("Verify")?;

            if first != second {
                eprintln!("Please try again");
                continue;
            }
        }

        break Ok(first.into());
    }
}

/// Derive the key from the PIN and Salt
fn derive_key(pin: &[u8], salt: &[u8]) -> Result<[u8; 32], Error> {
    let mut key = [0u8; 32];
    argon2id(None, pin, salt, None, None, 3, 1, 64 * 1024, &mut key)?;
    Ok(key)
}

/// Seal the actual encryption key with the PIN. This is then encrypted by the TPM
///
/// ## Errors
///
/// If the TPM couldn't generate bytes, the pin couldn't be acquired, or OpenSSL
/// could not encrypt the plaintext
#[allow(
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects,
    reason = "These are constants"
)]
pub fn seal(
    ctx: &mut Context,
    plaintext: &[u8],
    prompt: &str,
    name: &[u8],
) -> Result<BString, Error> {
    let pin = ask_pin(prompt, true)?;
    let salt = tpm::generate_bytes(ctx, SALT_LEN as u16)?;
    let nonce = tpm::generate_bytes(ctx, NONCE_LEN as u16)?;

    let key = derive_key(pin.as_slice(), salt.value())?;
    let mut tag = [0u8; TAG_LEN];

    let ciphertext = encrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(nonce.value()),
        name,
        plaintext,
        &mut tag,
    )?;

    let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + TAG_LEN + ciphertext.len());
    blob.extend_from_slice(salt.value());
    blob.extend_from_slice(nonce.value());
    blob.extend_from_slice(&tag);
    blob.extend_from_slice(&ciphertext);
    Ok(blob.into())
}

/// Unseal the encryption key with the PIN.
///
/// ## Errors
///
/// If OpenSSL could not decrypt the ciphertext blob, or a pin couldn't be acquired
pub fn unseal(blob: &[u8], prompt: &str, name: &[u8]) -> Result<BString, Error> {
    let header_len = SALT_LEN + NONCE_LEN + TAG_LEN;
    if blob.len() < header_len {
        return Err(Error::InvalidFormat("truncated blob"));
    }

    let salt = &blob[..SALT_LEN];
    let nonce = &blob[SALT_LEN..SALT_LEN + NONCE_LEN];
    let tag = &blob[SALT_LEN + NONCE_LEN..header_len];
    let ciphertext = &blob[header_len..];
    let pin = ask_pin(prompt, false)?;
    let key = derive_key(pin.as_slice(), salt)?;

    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &key,
        Some(nonce),
        name,
        ciphertext,
        tag,
    )?;

    Ok(plaintext.into())
}
