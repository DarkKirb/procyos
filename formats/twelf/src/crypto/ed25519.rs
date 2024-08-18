use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rand_core::{CryptoRng, RngCore};
use slh_dsa::signature::SignerMut;

use super::CryptoError;

pub const SIGNING_KEY_LENGTH: usize = ed25519_dalek::SECRET_KEY_LENGTH;
pub const VERIFYING_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
pub const SIGNATURE_LENGTH: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// The private signing key used for signing files.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigningKey(Ed25519SigningKey);

impl SigningKey {
    /// Generates a new private signing key using the provided random number generator.
    pub fn generate<R: RngCore + CryptoRng>(rand: &mut R) -> Self {
        Self(Ed25519SigningKey::generate(rand))
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
        buf.copy_from_slice(self.0.as_bytes());
        Ok(())
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
        let mut secret_key = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        secret_key.copy_from_slice(buf);
        Ok(Self(Ed25519SigningKey::from_bytes(&secret_key)))
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

    /// Calculates the public key derived from the private signing key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
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
            .map_err(CryptoError::InvalidSignature)?;
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
        buf.copy_from_slice(self.0.as_bytes());
        Ok(())
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
        let mut public_key = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        public_key.copy_from_slice(buf);
        Ok(Self(
            ed25519_dalek::VerifyingKey::from_bytes(&public_key)
                .map_err(CryptoError::InvalidPublicKeyEd25519)?,
        ))
    }
}
