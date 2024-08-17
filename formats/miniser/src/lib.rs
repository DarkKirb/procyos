//! Tiny serialization format for single-alloc serialization, no-alloc deserialization
#![feature(f128)]
#![feature(f16)]
#![feature(maybe_uninit_array_assume_init)]
#![feature(never_type)]
#![no_std]

#[cfg(test)]
extern crate std;

use core::error::Error;

use thiserror::Error;

pub mod de_impls;
mod ser_impls;
mod utils;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Error)]
pub enum SerializationError {
    #[error("The buffer size is not enough to serialize the value: {0} bytes required, but only {1} bytes available")]
    InsufficientBufferSize(usize, usize),
}

/// Basic serialization trait
pub trait Serialize {
    /// Returns the number of bytes required to serialize this value
    fn bytes_required(&self) -> usize;
    /// Serializes this value into a slice of bytes, returning the slice after writing
    ///
    /// # Errors
    /// This method may return an error if the buffer size is not enough to serialize the value
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], SerializationError>;
}

/// Basic deserialization trait
pub trait Deserialize<'de> {
    type Error: Error;
    type Target: 'de;
    /// Deserializes a value from a slice of bytes, modifying the start of the slice
    /// # Errors
    /// This function returns an error if the buffer does not contain enough data to deserialize the value, or if the data is invalid
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error>;
    /// Peeks at the size of the next value in the buffer without consuming it
    /// # Errors
    /// This function returns an error if the buffer does not contain enough data to deserialize the value, or if the data is invalid
    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error>;
}
