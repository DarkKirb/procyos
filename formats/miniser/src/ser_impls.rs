use crate::{utils::ZigZag, Serialize};

impl Serialize for bool {
    fn bytes_required(&self) -> usize {
        1
    }

    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(crate::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        buf[0] = u8::from(*self);
        Ok(&mut buf[1..])
    }
}

impl Serialize for u8 {
    fn bytes_required(&self) -> usize {
        1
    }

    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(crate::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        buf[0] = *self;
        Ok(&mut buf[1..])
    }
}

impl Serialize for i8 {
    fn bytes_required(&self) -> usize {
        1
    }

    #[expect(clippy::cast_sign_loss, reason = "Intended here")]
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(crate::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        buf[0] = *self as u8;
        Ok(&mut buf[1..])
    }
}

// The base integer type used is u128
impl Serialize for u128 {
    fn bytes_required(&self) -> usize {
        ((Self::BITS - self.leading_zeros()).div_ceil(7)).max(1) as usize
    }

    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        let bytes_required = self.bytes_required();
        if buf.len() < bytes_required {
            return Err(crate::SerializationError::InsufficientBufferSize(
                bytes_required,
                buf.len(),
            ));
        }
        let mut v = *self;

        for i in (0..bytes_required).rev() {
            let byte = (v & 0x7F) as u8;
            buf[i] = byte | if i == bytes_required - 1 { 0 } else { 0x80 };
            v >>= 7;
        }

        Ok(&mut buf[bytes_required..])
    }
}

impl Serialize for i128 {
    fn bytes_required(&self) -> usize {
        self.zigzag_encode().bytes_required()
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        self.zigzag_encode().serialize(buf)
    }
}

impl Serialize for u64 {
    fn bytes_required(&self) -> usize {
        u128::from(*self).bytes_required()
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        u128::from(*self).serialize(buf)
    }
}

impl Serialize for i64 {
    fn bytes_required(&self) -> usize {
        self.zigzag_encode().bytes_required()
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        self.zigzag_encode().serialize(buf)
    }
}

impl Serialize for usize {
    fn bytes_required(&self) -> usize {
        (*self as u128).bytes_required()
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        (*self as u128).serialize(buf)
    }
}

impl Serialize for isize {
    fn bytes_required(&self) -> usize {
        self.zigzag_encode().bytes_required()
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        self.zigzag_encode().serialize(buf)
    }
}

impl Serialize for u32 {
    fn bytes_required(&self) -> usize {
        u128::from(*self).bytes_required()
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        u128::from(*self).serialize(buf)
    }
}

impl Serialize for i32 {
    fn bytes_required(&self) -> usize {
        self.zigzag_encode().bytes_required()
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        self.zigzag_encode().serialize(buf)
    }
}

impl Serialize for u16 {
    fn bytes_required(&self) -> usize {
        u128::from(*self).bytes_required()
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        u128::from(*self).serialize(buf)
    }
}

impl Serialize for i16 {
    fn bytes_required(&self) -> usize {
        self.zigzag_encode().bytes_required()
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        self.zigzag_encode().serialize(buf)
    }
}

impl Serialize for char {
    fn bytes_required(&self) -> usize {
        (*self as u32).bytes_required()
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        (*self as u32).serialize(buf)
    }
}

impl Serialize for f16 {
    fn bytes_required(&self) -> usize {
        2
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(crate::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        buf[0..2].copy_from_slice(&self.to_le_bytes());
        Ok(&mut buf[2..])
    }
}

impl Serialize for f32 {
    fn bytes_required(&self) -> usize {
        4
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(crate::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        buf[0..4].copy_from_slice(&self.to_le_bytes());
        Ok(&mut buf[4..])
    }
}

impl Serialize for f64 {
    fn bytes_required(&self) -> usize {
        8
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(crate::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        buf[0..8].copy_from_slice(&self.to_le_bytes());
        Ok(&mut buf[8..])
    }
}

impl Serialize for f128 {
    fn bytes_required(&self) -> usize {
        16
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(crate::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        buf[0..16].copy_from_slice(&self.to_le_bytes());
        Ok(&mut buf[16..])
    }
}

impl<const N: usize, T: Serialize> Serialize for [T; N] {
    fn bytes_required(&self) -> usize {
        self.iter().map(Serialize::bytes_required).sum()
    }

    fn serialize<'a>(
        &self,
        mut buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], crate::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(crate::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        for x in self {
            buf = x.serialize(buf)?;
        }
        Ok(buf)
    }
}

impl<T: Serialize> Serialize for [T] {
    fn bytes_required(&self) -> usize {
        self.len().bytes_required() + self.iter().map(Serialize::bytes_required).sum::<usize>()
    }

    fn serialize<'a>(
        &self,
        mut buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], crate::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(crate::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        buf = self.len().serialize(buf)?;
        for x in self {
            buf = x.serialize(buf)?;
        }
        Ok(buf)
    }
}

impl Serialize for ! {
    fn bytes_required(&self) -> usize {
        unreachable!();
    }

    fn serialize<'a>(&self, _: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        unreachable!();
    }
}

impl Serialize for str {
    fn bytes_required(&self) -> usize {
        self.as_bytes().bytes_required()
    }

    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        self.as_bytes().serialize(buf)
    }
}

impl Serialize for () {
    fn bytes_required(&self) -> usize {
        0
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        Ok(buf)
    }
}

impl<A: Serialize> Serialize for (A,) {
    fn bytes_required(&self) -> usize {
        self.0.bytes_required()
    }
    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        self.0.serialize(buf)
    }
}

impl<A: Serialize, B: Serialize> Serialize for (A, B) {
    fn bytes_required(&self) -> usize {
        self.0.bytes_required() + self.1.bytes_required()
    }
    fn serialize<'a>(
        &self,
        mut buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], crate::SerializationError> {
        buf = self.0.serialize(buf)?;
        self.1.serialize(buf)
    }
}

impl<A: Serialize> Serialize for Option<A> {
    fn bytes_required(&self) -> usize {
        self.as_ref().map_or(1, |x| 1 + x.bytes_required())
    }

    fn serialize<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], crate::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(crate::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        if let Some(x) = self {
            buf[0] = 0b01;
            x.serialize(&mut buf[1..])
        } else {
            buf[0] = 0b00;
            Ok(&mut buf[1..])
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Serialize;

    #[test]
    fn ensure_u128_len() {
        assert_eq!(0u128.bytes_required(), 1);
        assert_eq!(1u128.bytes_required(), 1);
        assert_eq!(127u128.bytes_required(), 1);
        assert_eq!(128u128.bytes_required(), 2);
        assert_eq!(16383u128.bytes_required(), 2);
        assert_eq!(16384u128.bytes_required(), 3);
        assert_eq!(2_097_151_u128.bytes_required(), 3);
        assert_eq!(2_097_152_u128.bytes_required(), 4);
    }
}
