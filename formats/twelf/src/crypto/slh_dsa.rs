use rand_core::{CryptoRng, RngCore};
use slh_dsa::{
    signature::{Keypair, SignerMut},
    Shake128s, Signature,
};

use super::CryptoError;

type SlhDsaSigningKey = slh_dsa::SigningKey<Shake128s>;
type SlhDsaVerifyingKey = slh_dsa::VerifyingKey<Shake128s>;

pub const SIGNING_KEY_LENGTH: usize = 64;
pub const VERIFYING_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 7856;

/// The private signing key used for signing files.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigningKey(SlhDsaSigningKey);

impl SigningKey {
    /// Generates a new private signing key using the provided random number generator.
    pub fn generate<R: RngCore + CryptoRng>(rand: &mut R) -> Self {
        Self(SlhDsaSigningKey::new(rand))
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
        buf.copy_from_slice(self.0.to_bytes().as_slice());
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
        Ok(Self(SlhDsaSigningKey::try_from(buf)?))
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
pub struct VerifyingKey(SlhDsaVerifyingKey);

impl VerifyingKey {
    /// Verifies the detached signature of a message using the public verifying key, and returns a boolean indicating whether the signature is valid.
    ///
    /// # Errors
    ///
    /// This function returns an error if the message has been tampered with.
    pub fn verify_detached(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let sig = Signature::try_from(signature)?;
        self.0
            .try_verify_with_context(message, &[], &sig)
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
        buf.copy_from_slice(self.0.to_bytes().as_slice());
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
        Ok(Self(SlhDsaVerifyingKey::try_from(buf)?))
    }
}
