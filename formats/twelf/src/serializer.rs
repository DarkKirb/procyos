//! Serializer for TWELF files

use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::{CryptoError, PrivateSigningKey, SIGNATURE_LENGTH};
pub use crate::deserializer::{Architecture, X64Subarchitecture};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TWELF<'a> {
    signing_key: PrivateSigningKey,
    files: Vec<TWELFFile<'a>>,
}

impl<'a> TWELF<'a> {
    #[must_use]
    pub const fn new(signing_key: PrivateSigningKey) -> Self {
        Self {
            signing_key,
            files: Vec::new(),
        }
    }

    pub fn add_file(&mut self, file: TWELFFile<'a>) {
        self.files.push(file);
    }

    /// Serializes the TWELF into a byte buffer
    ///
    /// # Panics
    /// this function panics if you have more than 4 billion files
    ///
    /// # Errors
    /// This function returns an error if the signing fails.
    pub fn serialize(&mut self) -> Result<Vec<u8>, CryptoError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"TWLF"); // Magic number
        buf.extend_from_slice(&1u32.to_le_bytes()); // Version
        let files: u32 = self
            .files
            .len()
            .try_into()
            .expect("Number of files must fit in u32");
        buf.extend_from_slice(&files.to_le_bytes()); // Number of files
        buf.extend_from_slice(&self.signing_key.verifying_key().key_id().serialize()); // Key ID
        buf.extend_from_slice(b"\0\0\0"); // Padding
        buf.extend_from_slice(&vec![0u8; 56 * self.files.len()]); // Reserving file metadata
        let signed_length = buf.len();
        buf.extend_from_slice(&[0u8; SIGNATURE_LENGTH]); // Reserving signature
        for (i, file) in self.files.iter().enumerate() {
            file.serialize(i, &mut buf);
        }
        let signature = self.signing_key.sign(&buf[..signed_length])?;
        buf[signed_length..signed_length + SIGNATURE_LENGTH].copy_from_slice(&signature);
        Ok(buf)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TWELFFile<'a> {
    architecture: Architecture,
    data: &'a [u8],
}

impl<'a> TWELFFile<'a> {
    #[must_use]
    pub const fn new(data: &'a [u8], architecture: Architecture) -> Self {
        TWELFFile { architecture, data }
    }

    fn serialize(&self, i: usize, file_buf: &mut Vec<u8>) {
        let i = 48 + 56 * i;
        match self.architecture {
            Architecture::X64(subarch) => {
                file_buf[i..i + 4].copy_from_slice(&62u32.to_le_bytes());
                file_buf[i + 4..i + 8].copy_from_slice(&(subarch as u32).to_le_bytes());
                let file_buf_len = file_buf.len();
                file_buf[i + 8..i + 16].copy_from_slice(&(file_buf_len as u64).to_le_bytes());
                file_buf[i + 16..i + 24].copy_from_slice(&(self.data.len() as u64).to_le_bytes());
                file_buf[i + 24..i + 56].copy_from_slice(
                    blake3::Hasher::new()
                        .update(self.data)
                        .finalize()
                        .as_bytes(),
                );
                file_buf.extend_from_slice(self.data);
            }
        }
    }
}
