//! Ordered collections built by insertion.
//!
//! `collect::<BTreeMap<_, _>>()` sorts what it collects with a comparator
//! that is generic over the iterator's type, so every call site compiles a
//! whole sort of its own: in the WebAssembly module, about 20 KB each.
//! [`CollectMap::collect_map`] inserts instead, with the map's own code,
//! which each key and value type compiles once. The map is the same: a key
//! met twice keeps the value met last, as `collect` keeps it.

use std::collections::BTreeMap;

/// Collects pairs into a [`BTreeMap`] by insertion.
pub trait CollectMap<K, V>: Iterator<Item = (K, V)> + Sized {
    /// The map of these pairs, the last value of a key met twice.
    fn collect_map(self) -> BTreeMap<K, V>
    where
        K: Ord,
    {
        let mut map = BTreeMap::new();
        for (key, value) in self {
            map.insert(key, value);
        }
        map
    }
}

impl<K, V, I: Iterator<Item = (K, V)>> CollectMap<K, V> for I {}

#[cfg(test)]
mod tests {
    use super::CollectMap;
    use std::collections::BTreeMap;

    #[test]
    fn it_collects_as_collect_does() {
        let pairs = vec![(3, "c"), (1, "a"), (3, "C"), (2, "b"), (1, "A")];
        let collected: BTreeMap<_, _> = pairs.clone().into_iter().collect();
        assert_eq!(pairs.into_iter().collect_map(), collected);
        let empty: Vec<(u8, u8)> = Vec::new();
        assert!(empty.into_iter().collect_map().is_empty());
    }
}
