//! Protocol for kernel startup info
#![no_std]
extern crate alloc;

use core::fmt::Display;

use alloc::vec::Vec;
use miniser::{
    de_impls::{ArchivedSlice, BoolError, OptionError, SliceError, U64Error, U8Error},
    Deserialize, Serialize,
};
use thiserror::Error;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoryType {
    Free,
    Reserved,
}

impl Serialize for MemoryType {
    fn bytes_required(&self) -> usize {
        1
    }

    fn serialize<'a>(
        &self,
        buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], miniser::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(miniser::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        buf[0] = match self {
            Self::Free => 0,
            Self::Reserved => 1,
        };
        Ok(&mut buf[1..])
    }
}

impl<'de> Deserialize<'de> for MemoryType {
    type Error = BoolError;

    type Target = Self;

    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        match u8::deserialize(buf)? {
            0 => Ok(Self::Free),
            1 => Ok(Self::Reserved),
            v => Err(BoolError::InvalidBooleanValue(v)),
        }
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        Ok(u8::peek_size(buf)?)
    }
}

#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct MemoryMapEntry {
    pub base_addr: usize,
    pub length: usize,
    pub memory_type: MemoryType,
}

impl Serialize for MemoryMapEntry {
    fn bytes_required(&self) -> usize {
        self.base_addr.bytes_required()
            + self.length.bytes_required()
            + self.memory_type.bytes_required()
    }
    fn serialize<'a>(
        &self,
        mut buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], miniser::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(miniser::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        buf = self.base_addr.serialize(buf)?;
        buf = self.length.serialize(buf)?;
        buf = self.memory_type.serialize(buf)?;
        Ok(buf)
    }
}

#[derive(Copy, Clone, Debug, Error)]
pub enum MemoryMapEntryError {
    #[error("Couldn't deserialize u64 value: {0}")]
    U64DecodeError(#[from] U64Error),
    #[error("Couldn’t decode memory type value: {0}")]
    MemoryTypeError(#[from] BoolError),
}

impl<'de> Deserialize<'de> for MemoryMapEntry {
    type Error = MemoryMapEntryError;

    type Target = Self;

    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        let base_addr = usize::deserialize(buf)?;
        let length = usize::deserialize(buf)?;
        let memory_type = MemoryType::deserialize(buf)?;
        Ok(Self::new(base_addr, length, memory_type))
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        let base_addr = usize::peek_size(buf)?;
        let length = usize::peek_size(buf)?;
        let memory_type = MemoryType::peek_size(buf)?;
        Ok(base_addr + length + memory_type)
    }
}

impl MemoryMapEntry {
    #[must_use]
    pub const fn new(base_addr: usize, length: usize, memory_type: MemoryType) -> Self {
        Self {
            base_addr,
            length,
            memory_type,
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum PixelFormat {
    Rgb,
    Bgr,
}

impl Serialize for PixelFormat {
    fn bytes_required(&self) -> usize {
        1
    }

    fn serialize<'a>(
        &self,
        buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], miniser::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(miniser::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        buf[0] = match self {
            Self::Rgb => 0,
            Self::Bgr => 1,
        };
        Ok(&mut buf[1..])
    }
}

impl<'de> Deserialize<'de> for PixelFormat {
    type Error = BoolError;

    type Target = Self;

    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        match u8::deserialize(buf)? {
            0 => Ok(Self::Rgb),
            1 => Ok(Self::Bgr),
            v => Err(BoolError::InvalidBooleanValue(v)),
        }
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        Ok(u8::peek_size(buf)?)
    }
}

#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct Framebuffer {
    pub width: u32,
    pub height: u32,
    pub pixel_format: PixelFormat,
    pub buffer_paddr: usize,
    pub buffer_stride: usize,
}

impl<'de> Deserialize<'de> for Framebuffer {
    type Error = MemoryMapEntryError;

    type Target = Self;

    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        let width = u32::deserialize(buf)?;
        let height = u32::deserialize(buf)?;
        let pixel_format = PixelFormat::deserialize(buf)?;
        let buffer_paddr = usize::deserialize(buf)?;
        let buffer_stride = usize::deserialize(buf)?;
        Ok(Self::new(
            width,
            height,
            pixel_format,
            buffer_paddr,
            buffer_stride,
        ))
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        let width = u32::peek_size(buf)?;
        let height = u32::peek_size(buf)?;
        let pixel_format = PixelFormat::peek_size(buf)?;
        let buffer_paddr = usize::peek_size(buf)?;
        let buffer_stride = usize::peek_size(buf)?;
        Ok(width + height + pixel_format + buffer_paddr + buffer_stride)
    }
}

impl Serialize for Framebuffer {
    fn bytes_required(&self) -> usize {
        self.width.bytes_required()
            + self.height.bytes_required()
            + self.pixel_format.bytes_required()
            + self.buffer_paddr.bytes_required()
            + self.buffer_stride.bytes_required()
    }

    fn serialize<'a>(
        &self,
        mut buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], miniser::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(miniser::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        buf = self.width.serialize(buf)?;
        buf = self.height.serialize(buf)?;
        buf = self.pixel_format.serialize(buf)?;
        buf = self.buffer_paddr.serialize(buf)?;
        buf = self.buffer_stride.serialize(buf)?;
        Ok(buf)
    }
}

impl Framebuffer {
    #[must_use]
    pub const fn new(
        width: u32,
        height: u32,
        pixel_format: PixelFormat,
        buffer_paddr: usize,
        buffer_stride: usize,
    ) -> Self {
        Self {
            width,
            height,
            pixel_format,
            buffer_paddr,
            buffer_stride,
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct KernelStartInfo {
    pub version: u32,
    pub memory_map: Vec<MemoryMapEntry>,
    pub framebuffer: Option<Framebuffer>,
    pub pagetable_vaddr: usize,
    pub cma_vaddr: usize,
    pub cma_size: usize,
    pub random_seed: [u8; 32],
}

impl KernelStartInfo {
    #[must_use]
    pub const fn new(
        memory_map: Vec<MemoryMapEntry>,
        framebuffer: Option<Framebuffer>,
        pagetable_vaddr: usize,
        cma_vaddr: usize,
        cma_size: usize,
        random_seed: [u8; 32],
    ) -> Self {
        Self {
            version: 1,
            memory_map,
            framebuffer,
            pagetable_vaddr,
            cma_vaddr,
            cma_size,
            random_seed,
        }
    }
}

impl Serialize for KernelStartInfo {
    fn bytes_required(&self) -> usize {
        self.version.bytes_required()
            + self.memory_map.bytes_required()
            + self.framebuffer.bytes_required()
            + self.pagetable_vaddr.bytes_required()
            + self.cma_vaddr.bytes_required()
            + self.cma_size.bytes_required()
            + self.random_seed.bytes_required()
    }

    fn serialize<'a>(
        &self,
        mut buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], miniser::SerializationError> {
        if buf.len() < self.bytes_required() {
            return Err(miniser::SerializationError::InsufficientBufferSize(
                self.bytes_required(),
                buf.len(),
            ));
        }
        buf = self.version.serialize(buf)?;
        buf = self.memory_map.serialize(buf)?;
        buf = self.framebuffer.serialize(buf)?;
        buf = self.pagetable_vaddr.serialize(buf)?;
        buf = self.cma_vaddr.serialize(buf)?;
        buf = self.cma_size.serialize(buf)?;
        buf = self.random_seed.serialize(buf)?;
        Ok(buf)
    }
}

#[derive(Debug)]
pub enum ArchivedKernelStartInfoError<'de> {
    U32DecodeError(U64Error),
    InvalidVersionNumber(u32),
    MemoryMapError(SliceError<'de, MemoryMapEntry>),
    OptionError(OptionError<'de, Framebuffer>),
    U8DecodeError(U8Error),
}

impl Display for ArchivedKernelStartInfoError<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::U32DecodeError(err) => write!(f, "Couldn't deserialize u32: {err}"),
            Self::InvalidVersionNumber(v) => write!(f, "Invalid version number: {v}"),
            Self::MemoryMapError(err) => write!(f, "Couldn't decode memory map: {err}"),
            Self::OptionError(err) => write!(f, "Couldn't decode framebuffer option: {err}"),
            Self::U8DecodeError(err) => write!(f, "Couldn't deserialize u8: {err}"),
        }
    }
}

impl core::error::Error for ArchivedKernelStartInfoError<'_> {}

#[derive(Debug, Clone)]
pub struct ArchivedKernelStartInfo<'de> {
    pub version: u32,
    pub memory_map: ArchivedSlice<'de, MemoryMapEntry>,
    pub framebuffer: Option<Framebuffer>,
    pub pagetable_vaddr: usize,
    pub cma_vaddr: usize,
    pub cma_size: usize,
    pub random_seed: [u8; 32],
}

impl<'de> Deserialize<'de> for KernelStartInfo {
    type Error = ArchivedKernelStartInfoError<'de>;

    type Target = ArchivedKernelStartInfo<'de>;

    fn deserialize(buf: &mut &'de [u8]) -> Result<Self::Target, Self::Error> {
        let version =
            u32::deserialize(buf).map_err(ArchivedKernelStartInfoError::U32DecodeError)?;
        if version != 1 {
            return Err(ArchivedKernelStartInfoError::InvalidVersionNumber(version));
        }
        let memory_map = <[MemoryMapEntry]>::deserialize(buf)
            .map_err(ArchivedKernelStartInfoError::MemoryMapError)?;
        let framebuffer =
            Option::deserialize(buf).map_err(ArchivedKernelStartInfoError::OptionError)?;
        let pagetable_vaddr =
            usize::deserialize(buf).map_err(ArchivedKernelStartInfoError::U32DecodeError)?;
        let cma_vaddr =
            usize::deserialize(buf).map_err(ArchivedKernelStartInfoError::U32DecodeError)?;
        let cma_size =
            usize::deserialize(buf).map_err(ArchivedKernelStartInfoError::U32DecodeError)?;
        let random_seed =
            <[u8; 32]>::deserialize(buf).map_err(ArchivedKernelStartInfoError::U8DecodeError)?;
        Ok(ArchivedKernelStartInfo {
            version,
            memory_map,
            framebuffer,
            pagetable_vaddr,
            cma_vaddr,
            cma_size,
            random_seed,
        })
    }

    fn peek_size(buf: &mut &'de [u8]) -> Result<usize, Self::Error> {
        let mut size = 0;
        size += u32::peek_size(buf).map_err(ArchivedKernelStartInfoError::U32DecodeError)?;
        size += <[MemoryMapEntry]>::peek_size(buf)
            .map_err(ArchivedKernelStartInfoError::MemoryMapError)?;
        size += Option::peek_size(buf).map_err(ArchivedKernelStartInfoError::OptionError)?;
        size += usize::peek_size(buf).map_err(ArchivedKernelStartInfoError::U32DecodeError)?;
        size += usize::peek_size(buf).map_err(ArchivedKernelStartInfoError::U32DecodeError)?;
        size += usize::peek_size(buf).map_err(ArchivedKernelStartInfoError::U32DecodeError)?;
        size += <[u8; 32]>::peek_size(buf).map_err(ArchivedKernelStartInfoError::U8DecodeError)?;
        Ok(size)
    }
}
