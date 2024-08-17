//! TWELF signature algorithm

use core::hash::Hasher;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use ed25519_dalek::{ed25519::signature::SignerMut, SignatureError, SigningKey, VerifyingKey};
#[cfg(feature = "alloc")]
use fallible_collections::{TryCollect, TryReserveError};
use phf::PhfHash;
use phf_shared::{FmtConst, PhfBorrow};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

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
    InvalidSignatureEd25519(SignatureError),
    #[error("Invalid public key format {0} (expected 2)")]
    InvalidPublicKeyFormat(u8),
    #[error("Ed25519 Public key was invalid")]
    InvalidPublicKeyEd25519(SignatureError),
    #[error("Invalid Key ID format {0} (expected 0)")]
    InvalidKeyIdFormat(u8),
    #[cfg(feature = "alloc")]
    #[error("Failed to allocate memory: {0}")]
    FailedAllocation(#[from] TryReserveError),
}

pub const SIGNING_KEY_LENGTH: usize = 1 + ed25519_dalek::SECRET_KEY_LENGTH;
pub const VERIFYING_KEY_LENGTH: usize = 1 + ed25519_dalek::PUBLIC_KEY_LENGTH;
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// The private signing key used for signing files.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrivateSigningKey(SigningKey);

impl PrivateSigningKey {
    /// Generates a new private signing key using the provided random number generator.
    pub fn generate<R: RngCore + CryptoRng>(rand: &mut R) -> Self {
        Self(SigningKey::generate(rand))
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
        buf[0] = 0x01; // Private key format
        buf[1..].copy_from_slice(self.0.as_bytes());
        Ok(())
    }

    /// Serializes the private signing  key into a new vector.
    ///
    /// # Errors
    /// Returns an error if the allocation fails.
    #[cfg(feature = "alloc")]
    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
        let mut buf = [0u8; SIGNING_KEY_LENGTH];
        self.serialize_into(&mut buf)?;
        Ok(buf.try_collect()?)
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
        if buf[0] != 0x01 {
            return Err(CryptoError::InvalidPrivateKeyFormat(buf[0]));
        }
        let mut secret_key = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        secret_key.copy_from_slice(&buf[1..]);
        Ok(Self(SigningKey::from_bytes(&secret_key)))
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
        let sig = self.0.sign(message);
        signature_buf.copy_from_slice(&sig.to_bytes());
        Ok(())
    }

    /// Signs a message using the private signing key, and returns the signature as a buffer
    ///
    /// # Errors
    /// Returns an error if the allocation fails.
    #[cfg(feature = "alloc")]
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buf = [0u8; SIGNATURE_LENGTH];
        self.sign_into(message, &mut buf)?;
        Ok(buf.try_collect()?)
    }

    /// Calculates the public key derived from the private signing key.
    #[must_use]
    pub fn public_key(&self) -> PublicVerifyingKey {
        PublicVerifyingKey(self.0.verifying_key())
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicVerifyingKey(ed25519_dalek::VerifyingKey);

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
        let sig: [u8; SIGNATURE_LENGTH] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidBufferSize(signature.len(), SIGNATURE_LENGTH))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig);
        self.0
            .verify_strict(message, &sig)
            .map_err(CryptoError::InvalidSignatureEd25519)?;
        Ok(())
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
        buf[0] = 0x02; // Public key format
        buf[1..].copy_from_slice(self.0.as_bytes());
        Ok(())
    }

    /// Serializes the public verifying key into a new vector.
    ///
    /// # Errors
    /// Function returns an error if the allocation fails.
    #[cfg(feature = "alloc")]
    pub fn serialize(&self) -> Result<Vec<u8>, CryptoError> {
        let mut buf = [0u8; VERIFYING_KEY_LENGTH];
        self.serialize_into(&mut buf)?;
        Ok(buf.try_collect()?)
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
        if buf[0] != 0x02 {
            return Err(CryptoError::InvalidPublicKeyFormat(buf[0]));
        }
        let mut public_key = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        public_key.copy_from_slice(&buf[1..]);
        Ok(Self(
            VerifyingKey::from_bytes(&public_key).map_err(CryptoError::InvalidPublicKeyEd25519)?,
        ))
    }

    #[must_use]
    pub fn key_id(&self) -> KeyId {
        let pubkey = self.0.to_bytes();
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
        buf[0] = 0x00; // Key ID format
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
        if buf[0] != 0x00 {
            return Err(CryptoError::InvalidKeyIdFormat(buf[0]));
        }
        let mut key_id = [0u8; 32];
        let mut i = 0;
        while i < key_id.len() {
            key_id[i                    ] = buf[i + 1];
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
