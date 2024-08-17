use core::{
    error::Error,
    fmt::{self, Debug, Display},
    marker::PhantomData,
    mem::MaybeUninit,
    num::TryFromIntError,
    str,
};

use thiserror::Error;

use crate::{utils::ZigZag, Deserialize};

#[derive(Copy, Clone, Debug, Error)]
pub enum U8Error {
    #[error("Expected {0} bytes, but only {1} bytes available")]
    InvalidBuffersize(usize, usize),
}

impl<'de> Deserialize<'de> for u8 {
    type Error = U8Error;
    type Target = Self;

    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        if buf.is_empty() {
            return Err(U8Error::InvalidBuffersize(1, buf.len()));
        }
        let val = buf[0];
        *buf = &buf[1..];
        Ok(val)
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Err(U8Error::InvalidBuffersize(1, buf.len()));
        }
        *buf = &buf[1..];
        Ok(1)
    }
}

impl<'de> Deserialize<'de> for i8 {
    type Error = U8Error;
    type Target = Self;

    #[expect(clippy::cast_possible_wrap, reason = "Wrap is expected")]
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        u8::deserialize(buf).map(|v| v as Self)
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        u8::peek_size(buf)
    }
}

#[derive(Copy, Clone, Debug, Error)]
pub enum BoolError {
    #[error("Couldn’t decode u8 value: {0}")]
    U8DecodeError(#[from] U8Error),
    #[error("Invalid boolean value: {0}")]
    InvalidBooleanValue(u8),
}

impl<'de> Deserialize<'de> for bool {
    type Error = BoolError;

    type Target = Self;

    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        match u8::deserialize(buf)? {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(BoolError::InvalidBooleanValue(v)),
        }
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        Ok(u8::peek_size(buf)?)
    }
}

#[derive(Copy, Clone, Debug, Error)]
pub enum U128Error {
    #[error("Couldn’t decode u8 value: {0}")]
    U8DecodeError(#[from] U8Error),
    #[error("Invalid Varint Length: {0}")]
    InvalidVarintLength(usize),
}

impl<'de> Deserialize<'de> for u128 {
    type Error = U128Error;

    type Target = Self;

    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        let mut result = 0u128;
        let mut bits = 0;
        loop {
            let byte = u8::deserialize(buf)?;
            result <<= 7;
            result |= Self::from(byte & 0x7F);
            bits += 7;
            if bits > 133 {
                return Err(U128Error::InvalidVarintLength(bits));
            }
            if byte & 0x80 == 0 {
                break;
            }
        }
        Ok(result)
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        let mut bytes = 0;
        loop {
            let byte = u8::deserialize(buf)?;
            bytes += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        Ok(bytes)
    }
}

impl<'de> Deserialize<'de> for i128 {
    type Error = U128Error;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        u128::deserialize(buf).map(ZigZag::zigzag_decode)
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        u128::peek_size(buf)
    }
}

#[derive(Copy, Clone, Debug, Error)]
pub enum U64Error {
    #[error("Couldn’t Decode u128 Value: {0}")]
    U128DecodeError(#[from] U128Error),
    #[error("Invalid u64 Value: {0}")]
    InvalidU64Value(#[from] TryFromIntError),
}

impl<'de> Deserialize<'de> for u64 {
    type Error = U64Error;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        let v = u128::deserialize(buf)?;
        Ok(v.try_into()?)
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        Ok(u128::peek_size(buf)?)
    }
}

impl<'de> Deserialize<'de> for i64 {
    type Error = U64Error;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        u64::deserialize(buf).map(ZigZag::zigzag_decode)
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        u64::peek_size(buf)
    }
}

impl<'de> Deserialize<'de> for usize {
    type Error = U64Error;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        let v = u128::deserialize(buf)?;
        Ok(v.try_into()?)
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        Ok(u128::peek_size(buf)?)
    }
}

impl<'de> Deserialize<'de> for isize {
    type Error = U64Error;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        usize::deserialize(buf).map(ZigZag::zigzag_decode)
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        usize::peek_size(buf)
    }
}

impl<'de> Deserialize<'de> for u32 {
    type Error = U64Error;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        let v = u128::deserialize(buf)?;
        Ok(v.try_into()?)
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        Ok(u128::peek_size(buf)?)
    }
}

impl<'de> Deserialize<'de> for i32 {
    type Error = U64Error;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        u32::deserialize(buf).map(ZigZag::zigzag_decode)
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        u32::peek_size(buf)
    }
}

impl<'de> Deserialize<'de> for u16 {
    type Error = U64Error;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        let v = u128::deserialize(buf)?;
        Ok(v.try_into()?)
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        Ok(u128::peek_size(buf)?)
    }
}

impl<'de> Deserialize<'de> for i16 {
    type Error = U64Error;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        u16::deserialize(buf).map(ZigZag::zigzag_decode)
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        u16::peek_size(buf)
    }
}

#[derive(Copy, Clone, Debug, Error)]
pub enum CharError {
    #[error("Couldn’t Decode u32 Value: {0}")]
    U32DecodeError(#[from] U64Error),
    #[error("Invalid char Value: {0}")]
    InvalidCharValue(u32),
}

impl<'de> Deserialize<'de> for char {
    type Error = CharError;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        let v = u32::deserialize(buf)?;
        core::char::from_u32(v).ok_or(CharError::InvalidCharValue(v))
    }
    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        Ok(u32::peek_size(buf)?)
    }
}

impl<'de> Deserialize<'de> for f16 {
    type Error = U8Error;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        if buf.len() < 2 {
            return Err(U8Error::InvalidBuffersize(2, buf.len()));
        }
        let mut b = [0u8; 2];
        b.copy_from_slice(&buf[..2]);
        *buf = &buf[2..];
        Ok(Self::from_le_bytes(b))
    }
    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        if buf.len() < 2 {
            return Err(U8Error::InvalidBuffersize(2, buf.len()));
        }
        *buf = &buf[2..];
        Ok(2)
    }
}

impl<'de> Deserialize<'de> for f32 {
    type Error = U8Error;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        if buf.len() < 4 {
            return Err(U8Error::InvalidBuffersize(4, buf.len()));
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&buf[..4]);
        *buf = &buf[4..];
        Ok(Self::from_le_bytes(b))
    }
    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        if buf.len() < 4 {
            return Err(U8Error::InvalidBuffersize(4, buf.len()));
        }
        *buf = &buf[4..];
        Ok(4)
    }
}

impl<'de> Deserialize<'de> for f64 {
    type Error = U8Error;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        if buf.len() < 8 {
            return Err(U8Error::InvalidBuffersize(8, buf.len()));
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[..8]);
        *buf = &buf[8..];
        Ok(Self::from_le_bytes(b))
    }
    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        if buf.len() < 8 {
            return Err(U8Error::InvalidBuffersize(8, buf.len()));
        }
        *buf = &buf[8..];
        Ok(8)
    }
}

impl<'de> Deserialize<'de> for f128 {
    type Error = U8Error;
    type Target = Self;
    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        if buf.len() < 16 {
            return Err(U8Error::InvalidBuffersize(16, buf.len()));
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&buf[..16]);
        *buf = &buf[16..];
        Ok(Self::from_le_bytes(b))
    }
    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        if buf.len() < 16 {
            return Err(U8Error::InvalidBuffersize(16, buf.len()));
        }
        *buf = &buf[16..];
        Ok(16)
    }
}

#[derive(Copy, Clone, Debug, Error)]
pub enum StringError {
    #[error("Can’t decode size: {0}")]
    InvalidSize(#[from] U64Error),
    #[error("Invalid UTF-8 sequence: {0}")]
    InvalidUtf8(#[from] core::str::Utf8Error),
    #[error("Expected {0} bytes, but only {1} bytes available")]
    InvalidBuffersize(usize, usize),
}

impl<'de> Deserialize<'de> for str {
    type Error = StringError;

    type Target = &'de Self;

    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        let size = usize::deserialize(buf)?;
        if size > buf.len() {
            return Err(StringError::InvalidBuffersize(size, buf.len()));
        }
        let s = str::from_utf8(&buf[..size])?;
        *buf = &buf[size..];
        Ok(s)
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        let mut buf2 = *buf;
        let size = usize::deserialize(&mut buf2)?;
        let size_size = usize::peek_size(buf)?;
        if size > buf.len() {
            return Err(StringError::InvalidBuffersize(size, buf.len()));
        }
        Ok(size_size + size)
    }
}

pub enum OptionError<'a, T: Deserialize<'a>> {
    U8Error(U8Error),
    InvalidOptionValue(u8),
    DeserializeError(<T as Deserialize<'a>>::Error),
}

impl<'a, T: Deserialize<'a>> fmt::Debug for OptionError<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U8Error(arg0) => f.debug_tuple("U8Error").field(arg0).finish(),
            Self::InvalidOptionValue(arg0) => {
                f.debug_tuple("InvalidOptionValue").field(arg0).finish()
            }
            Self::DeserializeError(arg0) => f.debug_tuple("DeserializeError").field(arg0).finish(),
        }
    }
}

impl<'a, T: Deserialize<'a>> Display for OptionError<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U8Error(arg0) => write!(f, "U8Error: {arg0}"),
            Self::InvalidOptionValue(arg0) => write!(f, "InvalidOptionValue: {arg0}"),
            Self::DeserializeError(arg0) => write!(f, "DeserializeError: {arg0}"),
        }
    }
}

impl<'a, T: Deserialize<'a>> Error for OptionError<'a, T> {}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Option<T> {
    type Error = OptionError<'de, T>;

    type Target = Option<T::Target>;

    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        let variant = u8::deserialize(buf).map_err(OptionError::U8Error)?;
        match variant {
            0 => Ok(None),
            1 => {
                let value = T::deserialize(buf).map_err(OptionError::DeserializeError)?;
                Ok(Some(value))
            }
            _ => Err(OptionError::InvalidOptionValue(variant)),
        }
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        let variant = u8::deserialize(buf).map_err(OptionError::U8Error)?;
        match variant {
            0 => Ok(1), // None
            1 => T::peek_size(buf)
                .map(|size| 1 + size)
                .map_err(OptionError::DeserializeError),
            _ => Err(OptionError::InvalidOptionValue(variant)),
        }
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for [T; N] {
    type Error = T::Error;

    type Target = [T::Target; N];

    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        let mut result = [const { MaybeUninit::uninit() }; N];
        #[expect(
            clippy::needless_range_loop,
            reason = "Clippy false positive; uses try"
        )]
        for i in 0..N {
            result[i].write(T::deserialize(buf)?);
        }
        // SAFE: We initialized all elements
        unsafe { Ok(MaybeUninit::array_assume_init(result)) }
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        let mut size = 0;
        for _ in 0..N {
            size += T::peek_size(buf)?;
        }
        Ok(size)
    }
}

pub enum SliceError<'a, T: Deserialize<'a>> {
    U64Error(U64Error),
    DeserializeError(<T as Deserialize<'a>>::Error),
}

impl<'a, T: Deserialize<'a>> fmt::Debug for SliceError<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U64Error(arg0) => f.debug_tuple("U64Error").field(arg0).finish(),
            Self::DeserializeError(arg0) => f.debug_tuple("DeserializeError").field(arg0).finish(),
        }
    }
}

impl<'a, T: Deserialize<'a>> Display for SliceError<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U64Error(arg0) => write!(f, "U64Error: {arg0}"),
            Self::DeserializeError(arg0) => write!(f, "DeserializeError: {arg0}"),
        }
    }
}

impl<'a, T: Deserialize<'a>> Error for SliceError<'a, T> {}

pub struct ArchivedSlice<'de, T: Deserialize<'de>> {
    slice_buf: &'de [u8],
    _phantom: PhantomData<&'de [T]>,
}

impl<'de, T: Deserialize<'de> + 'de> Deserialize<'de> for [T] {
    type Error = SliceError<'de, T>;

    type Target = ArchivedSlice<'de, T>;

    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        let size = usize::deserialize(buf).map_err(SliceError::U64Error)?;
        let archived_slice_start = *buf;
        let mut byte_size = 0;
        for _ in 0..size {
            byte_size += T::peek_size(buf).map_err(SliceError::DeserializeError)?;
        }
        Ok(ArchivedSlice {
            slice_buf: &archived_slice_start[..byte_size],
            _phantom: PhantomData,
        })
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        let mut buf2 = *buf;
        let size = usize::deserialize(&mut buf2).map_err(SliceError::U64Error)?;
        let size_size = usize::peek_size(&mut buf2).map_err(SliceError::U64Error)?;
        let mut byte_size = 0;
        for _ in 0..size {
            byte_size += T::peek_size(buf).map_err(SliceError::DeserializeError)?;
        }
        Ok(size_size + byte_size)
    }
}

impl<'de, T: Deserialize<'de> + 'de> Clone for ArchivedSlice<'de, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'de, T: Deserialize<'de> + 'de> Copy for ArchivedSlice<'de, T> {}

#[expect(clippy::copy_iterator, reason = "Intended here")]
impl<'de, T: Deserialize<'de> + 'de> Iterator for ArchivedSlice<'de, T> {
    type Item = T::Target;

    fn next(&mut self) -> Option<Self::Item> {
        if self.slice_buf.is_empty() {
            None
        } else {
            T::deserialize(&mut self.slice_buf).ok()
        }
    }
}

impl<'de, T: Deserialize<'de> + 'de> Debug for ArchivedSlice<'de, T>
where
    T::Target: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        for item in *self {
            list.entry(&item);
        }
        list.finish()
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use crate::{Deserialize, Serialize};

    #[expect(
        clippy::needless_pass_by_value,
        reason = "Ease of use for test function"
    )]
    fn t<T: Serialize + for<'de> Deserialize<'de, Target = T> + PartialEq + core::fmt::Debug>(
        value: T,
    ) {
        let mut buf = vec![0u8; value.bytes_required()];
        value.serialize(&mut buf).unwrap();
        let mut bufp = &buf[..];
        assert_eq!(T::deserialize(&mut bufp).unwrap(), value);
        let mut bufp = &buf[..];
        assert_eq!(T::peek_size(&mut bufp).unwrap(), buf.len());
    }
    #[test]
    fn check_bidi() {
        for i in 0u8..=255 {
            t(i);
        }
        for i in -128i8..=127i8 {
            t(i);
        }
        for i in 0u16..=65535 {
            t(i);
        }
        t(69621u32);
        t(1e0);
        t(Some(1i32));
    }
}
