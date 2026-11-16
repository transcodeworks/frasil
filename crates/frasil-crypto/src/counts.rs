//! How many times this process ran each costly primitive: for tests and
//! measurements of what a procedure costs. The counts are process-wide and
//! relaxed; they decide nothing.

use core::sync::atomic::{AtomicU64, Ordering};

static MLDSA65_VERIFY: AtomicU64 = AtomicU64::new(0);
static MLDSA65_SIGN: AtomicU64 = AtomicU64::new(0);
static ED25519_VERIFY: AtomicU64 = AtomicU64::new(0);
static HPKE_OPEN: AtomicU64 = AtomicU64::new(0);
static AEAD_OPEN: AtomicU64 = AtomicU64::new(0);

/// The counts at one moment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// ML-DSA-65 verifications.
    pub mldsa65_verify: u64,
    /// ML-DSA-65 signatures made.
    pub mldsa65_sign: u64,
    /// Strict Ed25519 verifications.
    pub ed25519_verify: u64,
    /// HPKE opens with X-Wing: one X-Wing decapsulation each, whether or
    /// not the wrap then opens.
    pub hpke_open: u64,
    /// XChaCha20-Poly1305 opens, whether or not the tag verifies.
    pub aead_open: u64,
}

impl Counts {
    /// What ran between `earlier` and `self`.
    pub fn since(self, earlier: Counts) -> Counts {
        Counts {
            mldsa65_verify: self.mldsa65_verify - earlier.mldsa65_verify,
            mldsa65_sign: self.mldsa65_sign - earlier.mldsa65_sign,
            ed25519_verify: self.ed25519_verify - earlier.ed25519_verify,
            hpke_open: self.hpke_open - earlier.hpke_open,
            aead_open: self.aead_open - earlier.aead_open,
        }
    }
}

/// The counts now.
pub fn now() -> Counts {
    Counts {
        mldsa65_verify: MLDSA65_VERIFY.load(Ordering::Relaxed),
        mldsa65_sign: MLDSA65_SIGN.load(Ordering::Relaxed),
        ed25519_verify: ED25519_VERIFY.load(Ordering::Relaxed),
        hpke_open: HPKE_OPEN.load(Ordering::Relaxed),
        aead_open: AEAD_OPEN.load(Ordering::Relaxed),
    }
}

pub(crate) fn mldsa65_verify() {
    MLDSA65_VERIFY.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn mldsa65_sign() {
    MLDSA65_SIGN.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn ed25519_verify() {
    ED25519_VERIFY.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn hpke_open() {
    HPKE_OPEN.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn aead_open() {
    AEAD_OPEN.fetch_add(1, Ordering::Relaxed);
}
