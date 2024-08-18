//! Zero-copy deserializer for TWELF

use core::ops::Deref;

use thiserror::Error;

use crate::{
    crypto::{CryptoError, KeyId, PublicVerifyingKey, SIGNATURE_LENGTH},
    TryIndex,
};

#[derive(Debug, Error)]
pub enum DeserializationError {
    /// Invalid buffer size
    #[error("Invalid buffer size: expected at least {0}, got {1}")]
    InvalidBufferSize(usize, usize),

    /// Invalid magic number
    #[error("Invalid magic number: expected {0:X?}, got {1:X?}")]
    InvalidMagicNumber(u32, u32),

    /// Invalid version number
    #[error("Invalid version number: expected {0}, got {1}")]
    InvalidVersion(u32, u32),

    /// An error occurred while performing cryptography
    #[error("An error occurred while performing cryptography: {0}")]
    Crypto(#[from] CryptoError),

    /// Untrusted Key Error
    #[error("Key with ID {0:?} is not trusted")]
    UntrustedKey(KeyId),

    /// File is too big to be supported for the current system
    #[error("File is too big to be supported for the current system")]
    FileTooBig,

    /// File not found
    #[error("File not found")]
    FileNotFound,

    /// Invalid Architecture Value
    #[error("Invalid architecture value")]
    InvalidArchitectureValue,
}

type Result<T> = core::result::Result<T, DeserializationError>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct TWELF<'a>(&'a [u8]);

impl<'a> TWELF<'a> {
    /// Loads a new TWELF from the provided buffer and Keyring
    ///
    /// # Errors
    /// This function returns an error if the provided file is invalid, too short, or the signature doesn’t match
    pub fn new<'b, D, M>(buf: &'a [u8], keyring: &M) -> Result<Self>
    where
        D: Deref<Target = PublicVerifyingKey> + 'b,
        M: for<'c> TryIndex<&'c KeyId, Output = &'b D>,
    {
        if buf.len() < 48 + SIGNATURE_LENGTH {
            return Err(DeserializationError::InvalidBufferSize(
                48 + SIGNATURE_LENGTH,
                buf.len(),
            ));
        }

        if &buf[0..4] != b"TWLF" {
            let mut a = [0; 4];
            a.copy_from_slice(&buf[0..4]);
            return Err(DeserializationError::InvalidMagicNumber(
                0x464C_5754,
                u32::from_le_bytes(a),
            ));
        }

        let version = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if version != 1 {
            return Err(DeserializationError::InvalidVersion(1, version));
        }

        let this = Self(buf);

        let key_id = this.key_id()?;

        let key = match keyring.try_index(&key_id) {
            Some(key) => *key,
            None => return Err(DeserializationError::UntrustedKey(key_id)),
        };

        if buf.len() < 48 + SIGNATURE_LENGTH + this.num_files() * 56 {
            return Err(DeserializationError::InvalidBufferSize(
                48 + SIGNATURE_LENGTH + this.num_files() * 56,
                buf.len(),
            ));
        }

        key.verify(&buf[..(48 + SIGNATURE_LENGTH + this.num_files() * 56)])?;

        Ok(this)
    }

    /// Returns the number of files in the TWELF
    #[must_use]
    pub const fn num_files(&self) -> usize {
        u32::from_le_bytes([self.0[8], self.0[9], self.0[10], self.0[11]]) as usize
    }

    /// Returns the key ID of the TWELF
    ///
    /// # Errors
    /// Returns an error if the key ID is invalid
    pub fn key_id(&self) -> Result<KeyId> {
        Ok(KeyId::deserialize(&self.0[12..45])?)
    }

    /// Returns the file at the given index
    ///
    /// # Errors
    /// Returns an error if the file index is out of bounds, or the file metadata is invalid
    pub fn get_file(&self, index: usize) -> Result<TWELFFile<'a>> {
        if index >= self.num_files() {
            return Err(DeserializationError::FileNotFound);
        }
        let off = 48 + 56 * index;
        TWELFFile::new(&self.0[off..off + 56], *self)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TWELFFile<'a>(&'a [u8], TWELF<'a>);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum X64Subarchitecture {
    /// Base ISA
    V1 = 0,
    /// CMPXCHG16B, LAHF-SAHF, POPCNT, SSE3, SSE4.1, SSE4.2, SSSE3
    V2 = 1,
    /// AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, OSXSAVE
    V3 = 2,
    /// AVX512F, AVX512BW, AVX512CD, AVX512DQ, AVX512VL
    V4 = 3,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Architecture {
    X64(X64Subarchitecture),
}

impl<'a> TWELFFile<'a> {
    fn new(buf: &'a [u8], twelf: TWELF<'a>) -> Result<Self> {
        if buf.len() != 56 {
            return Err(DeserializationError::InvalidBufferSize(88, buf.len()));
        }
        let file = Self(buf, twelf);
        if file.end_off()? > twelf.0.len() {
            return Err(DeserializationError::InvalidBufferSize(
                file.end_off()?,
                buf.len(),
            ));
        }
        Ok(file)
    }

    fn start_off(&self) -> Result<usize> {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.0[8..16]);
        u64::from_le_bytes(buf)
            .try_into()
            .map_err(|_| DeserializationError::FileTooBig)
    }

    fn file_len(&self) -> Result<usize> {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.0[16..24]);
        u64::from_le_bytes(buf)
            .try_into()
            .map_err(|_| DeserializationError::FileTooBig)
    }

    fn end_off(&self) -> Result<usize> {
        self.start_off()?
            .checked_add(self.file_len()?)
            .ok_or(DeserializationError::FileTooBig)
    }

    /// Reads the file data from the TWELF
    ///
    /// # Errors
    /// This function returns an error if the file data is invalid or the hash does not match
    pub fn read(&self) -> Result<&'a [u8]> {
        let buf = &self.1 .0[self.start_off()?..self.end_off()?];
        // Before returning, verify that the file is valid
        let hash = blake3::Hasher::new().update(buf).finalize();
        let mut expected_hash = [0u8; 32];
        expected_hash.copy_from_slice(&buf[24..56]);

        if constant_time_eq::constant_time_eq_32(hash.as_bytes(), &expected_hash) {
            return Ok(buf);
        }

        Ok(buf)
    }

    /// Returns the architecture of the file
    ///
    /// # Errors
    /// Returns an error if the architecture value is invalid
    pub fn architecture(&self) -> Result<Architecture> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.0[0..4]);
        match u32::from_le_bytes(buf) {
            62 => {
                // x86_64
                buf.copy_from_slice(&self.0[4..8]);
                match u32::from_le_bytes(buf) {
                    0 => Ok(Architecture::X64(X64Subarchitecture::V1)),
                    1 => Ok(Architecture::X64(X64Subarchitecture::V2)),
                    2 => Ok(Architecture::X64(X64Subarchitecture::V3)),
                    3 => Ok(Architecture::X64(X64Subarchitecture::V4)),
                    _ => Err(DeserializationError::InvalidArchitectureValue),
                }
            }
            _ => Err(DeserializationError::InvalidArchitectureValue),
        }
    }
}
