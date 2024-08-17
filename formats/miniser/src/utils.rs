pub trait ZigZag {
    type ZigZagEncoded;

    fn zigzag_encode(self) -> Self::ZigZagEncoded;
    fn zigzag_decode(v: Self::ZigZagEncoded) -> Self;
}

impl ZigZag for i16 {
    type ZigZagEncoded = u16;

    #[expect(clippy::cast_sign_loss, reason = "Intended here")]
    fn zigzag_encode(self) -> Self::ZigZagEncoded {
        let v = self as Self::ZigZagEncoded;
        (v >> (Self::ZigZagEncoded::BITS - 1)) ^ (v << 1)
    }

    #[expect(clippy::cast_possible_wrap, reason = "Intended here")]
    fn zigzag_decode(v: Self::ZigZagEncoded) -> Self {
        (v >> 1) as Self ^ -((v & 1) as Self)
    }
}

impl ZigZag for i32 {
    type ZigZagEncoded = u32;

    #[expect(clippy::cast_sign_loss, reason = "Intended here")]
    fn zigzag_encode(self) -> Self::ZigZagEncoded {
        let v = self as Self::ZigZagEncoded;
        (v >> (Self::ZigZagEncoded::BITS - 1)) ^ (v << 1)
    }

    #[expect(clippy::cast_possible_wrap, reason = "Intended here")]
    fn zigzag_decode(v: Self::ZigZagEncoded) -> Self {
        (v >> 1) as Self ^ -((v & 1) as Self)
    }
}

impl ZigZag for i64 {
    type ZigZagEncoded = u64;

    #[expect(clippy::cast_sign_loss, reason = "Intended here")]
    fn zigzag_encode(self) -> Self::ZigZagEncoded {
        let v = self as Self::ZigZagEncoded;
        (v >> (Self::ZigZagEncoded::BITS - 1)) ^ (v << 1)
    }

    #[expect(clippy::cast_possible_wrap, reason = "Intended here")]
    fn zigzag_decode(v: Self::ZigZagEncoded) -> Self {
        (v >> 1) as Self ^ -((v & 1) as Self)
    }
}
impl ZigZag for i128 {
    type ZigZagEncoded = u128;

    #[expect(clippy::cast_sign_loss, reason = "Intended here")]
    fn zigzag_encode(self) -> Self::ZigZagEncoded {
        let v = self as Self::ZigZagEncoded;
        (v >> (Self::ZigZagEncoded::BITS - 1)) ^ (v << 1)
    }

    #[expect(clippy::cast_possible_wrap, reason = "Intended here")]
    fn zigzag_decode(v: Self::ZigZagEncoded) -> Self {
        (v >> 1) as Self ^ -((v & 1) as Self)
    }
}
impl ZigZag for isize {
    type ZigZagEncoded = usize;

    #[expect(clippy::cast_sign_loss, reason = "Intended here")]
    fn zigzag_encode(self) -> Self::ZigZagEncoded {
        let v = self as Self::ZigZagEncoded;
        (v >> (Self::ZigZagEncoded::BITS - 1)) ^ (v << 1)
    }

    #[expect(clippy::cast_possible_wrap, reason = "Intended here")]
    fn zigzag_decode(v: Self::ZigZagEncoded) -> Self {
        (v >> 1) as Self ^ -((v & 1) as Self)
    }
}
