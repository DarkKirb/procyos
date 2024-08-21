//! RNG Seeder
//!
//! Combines multiple RNG sources to generate a more secure random seed.
#![no_std]
#![feature(allocator_api)]

use core::alloc::Allocator;

use alloc::{alloc::Global, boxed::Box, vec::Vec};
use rand_core::RngCore;

extern crate alloc;

pub struct RngSeeder<'a, A: Allocator + Copy> {
    allocator: A,
    rngs: Vec<Box<dyn RngCore + 'a, A>, A>,
    seed_buf: [u8; 32],
    position: usize,
}

impl<'a, A: Allocator + Copy> RngSeeder<'a, A> {
    pub fn new_in(allocator: A) -> Self {
        Self {
            allocator,
            rngs: Vec::new_in(allocator),
            seed_buf: [0; 32],
            position: 32,
        }
    }

    pub fn add_rng(&mut self, rng: impl RngCore + 'a) {
        self.rngs.push(Box::new_in(rng, self.allocator));
    }

    pub fn reseed(&mut self) -> Result<(), rand_core::Error> {
        if self.rngs.is_empty() {
            panic!("Calling reseed without any RNGs added! Please add at least one RNG to the RngSeeder!");
        }
        let mut rand_buf = [0; 32];
        let mut hasher = blake3::Hasher::new();
        for rng in self.rngs.iter_mut() {
            rng.try_fill_bytes(&mut rand_buf)?;
            hasher.update(&rand_buf);
        }
        self.seed_buf
            .copy_from_slice(hasher.finalize().as_bytes().as_slice());
        self.position = 0;
        Ok(())
    }
}

impl<'a> RngSeeder<'a, Global> {
    pub fn new() -> Self {
        Self::new_in(Global)
    }
}

impl<'a> Default for RngSeeder<'a, Global> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, A: Allocator + Copy> RngCore for RngSeeder<'a, A> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf).unwrap();
        u32::from_ne_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf).unwrap();
        u64::from_ne_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap();
    }

    fn try_fill_bytes(&mut self, mut dest: &mut [u8]) -> Result<(), rand_core::Error> {
        while !dest.is_empty() {
            let next_chunk = dest.len().min(32 - self.position);
            dest[self.position..(self.position + next_chunk)]
                .copy_from_slice(&self.seed_buf[self.position..self.position + next_chunk]);
            self.position += next_chunk;
            if self.position > 31 {
                self.reseed()?;
            }
            dest = &mut dest[next_chunk..];
        }
        Ok(())
    }
}
