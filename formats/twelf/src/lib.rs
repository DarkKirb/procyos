#![cfg_attr(feature = "alloc", feature(allocator_api))]
#![cfg_attr(feature = "alloc", feature(try_with_capacity))]
#![no_std]

#[cfg(feature = "alloc")]
use core::{alloc::Allocator, borrow::Borrow};

#[cfg(feature = "alloc")]
use alloc::collections::btree_map::BTreeMap;
use phf::{Map, PhfHash};
use phf_shared::PhfBorrow;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod crypto;
pub mod deserializer;
#[cfg(feature = "picker")]
pub mod picker;
#[cfg(feature = "alloc")]
pub mod serializer;

pub trait TryIndex<Idx: ?Sized> {
    type Output: ?Sized;

    fn try_index(&self, index: Idx) -> Option<&Self::Output>;
}

#[cfg(feature = "alloc")]
impl<K, Q, V, A: Allocator + Clone> TryIndex<&Q> for BTreeMap<K, V, A>
where
    K: Borrow<Q> + Ord,
    Q: Ord + ?Sized,
{
    type Output = V;

    fn try_index(&self, key: &Q) -> Option<&Self::Output> {
        self.get(key)
    }
}

impl<'a, K, V, T> TryIndex<&'a T> for Map<K, V>
where
    T: Eq + PhfHash + ?Sized,
    K: PhfBorrow<T>,
{
    type Output = V;
    fn try_index(&self, k: &'a T) -> Option<&V> {
        self.get(k)
    }
}
