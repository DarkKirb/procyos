//! TWELF signature algorithm

use core::{hash::Hasher, hint::black_box};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use ed25519_dalek::SignatureError;
#[cfg(feature = "alloc")]
use fallible_collections::TryReserveError;
use phf::PhfHash;
use phf_shared::{FmtConst, PhfBorrow};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

pub mod ed25519;
pub mod slh_dsa;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("Invalid buffer size {0} (expected {1} bytes)")]
    InvalidBufferSize(usize, usize),
    #[error("Invalid private key format {0} (expected 1)")]
    InvalidPrivateKeyFormat(u8),
    #[error("Invalid signature buffer size {0} (expected {1} bytes)")]
    InvalidSignatureSize(usize, usize),
    #[error("Invalid Ed25519 Signature: {0}")]
    InvalidSignature(SignatureError),
    #[error("Invalid public key format {0} (expected 2)")]
    InvalidPublicKeyFormat(u8),
    #[error("Ed25519 Public key was invalid")]
    InvalidPublicKeyEd25519(SignatureError),
    #[error("Invalid Key ID format {0} (expected 0)")]
    InvalidKeyIdFormat(u8),
    #[cfg(feature = "alloc")]
    #[error("Failed to allocate memory: {0}")]
    FailedAllocation(#[from] TryReserveError),
    #[error("Signature error: {0}")]
    Ed25519Error(ed25519_dalek::ed25519::Error),
    #[error("Signature is invalid.")]
    InvalidCombinedSignature,
}

impl From<ed25519_dalek::ed25519::Error> for CryptoError {
    fn from(value: ed25519_dalek::ed25519::Error) -> Self {
        Self::Ed25519Error(value)
    }
}

pub const SIGNING_KEY_LENGTH: usize = 1 + ed25519::SIGNING_KEY_LENGTH + slh_dsa::SIGNING_KEY_LENGTH;
pub const VERIFYING_KEY_LENGTH: usize =
    1 + ed25519::VERIFYING_KEY_LENGTH + slh_dsa::VERIFYING_KEY_LENGTH;
pub const SIGNATURE_LENGTH: usize = ed25519::SIGNATURE_LENGTH + slh_dsa::SIGNATURE_LENGTH;

/// The private signing key used for signing files.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrivateSigningKey(ed25519::SigningKey, slh_dsa::SigningKey);

impl PrivateSigningKey {
    /// Generates a new private signing key using the provided random number generator.
    pub fn generate<R: RngCore + CryptoRng>(rand: &mut R) -> Self {
        Self(
            ed25519::SigningKey::generate(rand),
            slh_dsa::SigningKey::generate(rand),
        )
    }

    /// Serializes the private signing key into the provided buffer.
    ///
    /// # Errors
    /// This funciton returns an error if the provided buffer is not the correct size to hold the private key.
    pub fn serialize_into(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        if buf.len() != SIGNING_KEY_LENGTH {
            return Err(CryptoError::InvalidBufferSize(
                buf.len(),
                SIGNING_KEY_LENGTH,
            ));
        }
        buf[0] = 0x04; // Private key format
        self.0
            .serialize_into(&mut buf[1..=ed25519::SIGNING_KEY_LENGTH])?;
        self.1
            .serialize_into(&mut buf[1 + ed25519::SIGNING_KEY_LENGTH..])?;
        Ok(())
    }

    /// Serializes the private signing  key into a new vector.
    ///
    /// # Errors
    /// Returns an error if the allocation fails.
    #[cfg(feature = "alloc")]
    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
        let mut buf = alloc::vec![0u8; SIGNING_KEY_LENGTH];
        self.serialize_into(&mut buf)?;
        Ok(buf)
    }

    /// Deserializes a private signing key from the provided buffer.
    ///
    /// # Errors
    /// This function returns an error if the provided buffer does not contain a valid private key.
    pub fn deserialize(buf: &[u8]) -> Result<Self, CryptoError> {
        if buf.len() != SIGNING_KEY_LENGTH {
            return Err(CryptoError::InvalidBufferSize(
                buf.len(),
                SIGNING_KEY_LENGTH,
            ));
        }
        if buf[0] != 0x04 {
            return Err(CryptoError::InvalidPrivateKeyFormat(buf[0]));
        }
        let (ed25519_sk, slh_dsa_sk) = buf[1..].split_at(ed25519::SIGNING_KEY_LENGTH);
        Ok(Self(
            ed25519::SigningKey::deserialize(ed25519_sk)?,
            slh_dsa::SigningKey::deserialize(slh_dsa_sk)?,
        ))
    }

    /// Signs a message using the private signing key.
    ///
    /// # Errors
    /// This function returns an error if the provided buffer doesn’t fit the signature.
    pub fn sign_into(
        &mut self,
        message: &[u8],
        signature_buf: &mut [u8],
    ) -> Result<(), CryptoError> {
        if signature_buf.len() != SIGNATURE_LENGTH {
            return Err(CryptoError::InvalidSignatureSize(
                signature_buf.len(),
                SIGNATURE_LENGTH,
            ));
        }
        self.0
            .sign_into(message, &mut signature_buf[..ed25519::SIGNATURE_LENGTH])?;
        self.1
            .sign_into(message, &mut signature_buf[ed25519::SIGNATURE_LENGTH..])?;
        Ok(())
    }

    /// Signs a message using the private signing key, and returns the signature as a buffer
    ///
    /// # Errors
    /// Returns an error if the allocation fails.
    #[cfg(feature = "alloc")]
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = alloc::vec![0u8; SIGNATURE_LENGTH];
        self.sign_into(message, &mut buf)?;
        Ok(buf)
    }

    /// Calculates the public key derived from the private signing key.
    #[must_use]
    pub fn verifying_key(&self) -> PublicVerifyingKey {
        PublicVerifyingKey(self.0.verifying_key(), self.1.verifying_key())
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicVerifyingKey(ed25519::VerifyingKey, slh_dsa::VerifyingKey);

impl PublicVerifyingKey {
    /// Verifies the attached signature of a message using the public verifying key.
    ///
    /// The signature is expected to be in the last `[SIGNATURE_LENGTH]` bytes of the provided buffer.
    ///
    /// # Errors
    ///
    /// This function returns an error if the message has been tampered with.
    pub fn verify(&self, message: &[u8]) -> Result<(), CryptoError> {
        let (message, signature) = message.split_at(message.len() - SIGNATURE_LENGTH);
        self.verify_detached(message, signature)
    }

    /// Verifies the detached signature of a message using the public verifying key, and returns a boolean indicating whether the signature is valid.
    ///
    /// # Errors
    ///
    /// This function returns an error if the message has been tampered with.
    pub fn verify_detached(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let (ed25519_sig, slh_dsa_sig) = signature.split_at(ed25519::SIGNATURE_LENGTH);
        let res1 = u8::from(self.0.verify_detached(message, ed25519_sig).is_ok());
        let res2 = u8::from(self.1.verify_detached(message, slh_dsa_sig).is_ok());
        if black_box(black_box(res1) & black_box(res2)) == 1 {
            Ok(())
        } else {
            Err(CryptoError::InvalidCombinedSignature)
        }
    }

    /// Serializes the public verifying key into the provided buffer.
    ///
    /// # Errors
    /// This funciton returns an error if the provided buffer is not the correct size to hold the private key.
    pub fn serialize_into(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        if buf.len() != VERIFYING_KEY_LENGTH {
            return Err(CryptoError::InvalidBufferSize(
                buf.len(),
                VERIFYING_KEY_LENGTH,
            ));
        }
        buf[0] = 0x05; // Public key format
        let (ed25519_vk, slh_dsa_vk) = buf[1..].split_at_mut(ed25519::VERIFYING_KEY_LENGTH);
        self.0.serialize_into(ed25519_vk)?;
        self.1.serialize_into(slh_dsa_vk)?;
        Ok(())
    }

    /// Serializes the public verifying key into a new vector.
    ///
    /// # Errors
    /// Function returns an error if the allocation fails.
    #[cfg(feature = "alloc")]
    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
        let mut buf = alloc::vec![0u8; VERIFYING_KEY_LENGTH];
        self.serialize_into(&mut buf)?;
        Ok(buf)
    }

    /// Deserializes a public verifying key from the provided buffer.
    ///
    /// # Errors
    /// This function returns an error if the provided buffer does not contain a valid private key.
    pub fn deserialize(buf: &[u8]) -> Result<Self, CryptoError> {
        if buf.len() != VERIFYING_KEY_LENGTH {
            return Err(CryptoError::InvalidBufferSize(
                buf.len(),
                VERIFYING_KEY_LENGTH,
            ));
        }
        if buf[0] != 0x05 {
            return Err(CryptoError::InvalidPublicKeyFormat(buf[0]));
        }
        let (ed25519_vk, slh_dsa_vk) = buf[1..].split_at(ed25519::VERIFYING_KEY_LENGTH);
        Ok(Self(
            ed25519::VerifyingKey::deserialize(ed25519_vk)?,
            slh_dsa::VerifyingKey::deserialize(slh_dsa_vk)?,
        ))
    }

    #[must_use]
    #[expect(
        clippy::missing_panics_doc,
        reason = "The function doesn't actually panic"
    )]
    pub fn key_id(&self) -> KeyId {
        let mut pubkey = [0u8; VERIFYING_KEY_LENGTH];
        self.serialize_into(&mut pubkey).unwrap();
        let digest = blake3::Hasher::new().update(&pubkey).finalize();

        KeyId(*digest.as_bytes())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
#[repr(transparent)]
pub struct KeyId(pub [u8; 32]);

impl KeyId {
    /// Serializes the public key ID
    #[must_use]
    pub fn serialize(&self) -> [u8; 33] {
        let mut buf = [0u8; 33];
        buf[0] = 0x03; // Key ID format
        buf[1..].copy_from_slice(&self.0);
        buf
    }

    /// Deserialize a public key ID from the provided buffer
    ///
    /// # Errors
    /// This function returns an error if the provided buffer does not contain a valid public key ID
    pub const fn deserialize(buf: &[u8]) -> Result<Self, CryptoError> {
        if buf.len() != 33 {
            return Err(CryptoError::InvalidBufferSize(buf.len(), 33));
        }
        if buf[0] != 0x03 {
            return Err(CryptoError::InvalidKeyIdFormat(buf[0]));
        }
        let mut key_id = [0u8; 32];
        let mut i = 0;
        while i < key_id.len() {
            key_id[i] = buf[i + 1];
            i += 1;
        }
        Ok(Self(key_id))
    }
}

impl FmtConst for KeyId {
    fn fmt_const(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl PhfHash for KeyId {
    fn phf_hash<H: Hasher>(&self, state: &mut H) {
        self.0.phf_hash(state);
    }
}

impl PhfBorrow<Self> for KeyId {
    fn borrow(&self) -> &Self {
        self
    }
}
