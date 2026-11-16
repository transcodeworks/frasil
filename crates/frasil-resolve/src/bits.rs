//! A fixed-size set of event indices.

/// A set of indices below a fixed bound, one bit each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Bits {
    words: Vec<u64>,
}

impl Bits {
    /// The empty set of indices below `len`.
    pub(crate) fn new(len: usize) -> Self {
        Self {
            words: vec![0; len.div_ceil(64)],
        }
    }

    pub(crate) fn insert(&mut self, index: usize) {
        self.words[index / 64] |= 1 << (index % 64);
    }

    pub(crate) fn contains(&self, index: usize) -> bool {
        self.words[index / 64] & (1 << (index % 64)) != 0
    }

    /// Whether every index of `self` is in `other`, which has the same
    /// bound.
    pub(crate) fn is_subset(&self, other: &Bits) -> bool {
        self.words
            .iter()
            .zip(&other.words)
            .all(|(mine, theirs)| mine & !theirs == 0)
    }

    /// The indices, smallest first.
    pub(crate) fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.words.iter().enumerate().flat_map(|(w, &word)| {
            let mut rest = word;
            core::iter::from_fn(move || {
                if rest == 0 {
                    return None;
                }
                let bit = rest.trailing_zeros() as usize;
                rest &= rest - 1;
                Some(w * 64 + bit)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Bits;

    #[test]
    fn insert_contains_iter_subset() {
        let mut a = Bits::new(130);
        for i in [0, 63, 64, 129] {
            a.insert(i);
        }
        assert!(a.contains(64) && !a.contains(65));
        assert_eq!(a.iter().collect::<Vec<_>>(), vec![0, 63, 64, 129]);
        let mut b = a.clone();
        b.insert(1);
        assert!(a.is_subset(&b) && !b.is_subset(&a));
    }
}
