//! Provides SHA2 based hash suites for SLH DSA
//! Uses Solana hashv on chain and uses Sha256 off chain through a small syscall shim
//! Passes message as a list of parts to minimize copying and to fit BPF constraints
//! Preserves parameter sets and sizes and keeps behavior aligned with FIPS 205

// TODO(tarcieri): fix `hybrid-array` deprecation warnings
#![allow(deprecated)]

extern crate alloc;

use core::fmt::Debug;
use alloc::vec::Vec;

use crate::hashes::HashSuite;
use crate::{
    address::Address, fors::ForsParams, hypertree::HypertreeParams, wots::WotsParams,
    xmss::XmssParams, ParameterSet,
};
use crate::{PkSeed, SkPrf, SkSeed};
use digest::{Digest, Mac};
use hmac::Hmac;
use hybrid_array::{Array, ArraySize};
use sha2::{Sha256, Sha512};
use typenum::{Diff, Sum, U, U128, U16, U24, U30, U32, U34, U39, U42, U47, U49, U64};

/// Computes a single SHA 256 digest
/// Uses `solana_program::hash::hashv` on chain and falls back to `Sha256` off chain
/// Accepts multiple parts as concatenated inputs
#[inline]
fn sha256_syscall(parts: &[&[u8]]) -> [u8; 32] {
    #[cfg(target_os = "solana")]
    {
        use solana_program::hash::hashv;
        hashv(parts).to_bytes()
    }
    #[cfg(not(target_os = "solana"))]
    {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..]);
        out
    }
}

/// Implements the MGF1 XOF
fn mgf1<H: Digest, L: ArraySize>(seed: &[u8]) -> Array<u8, L> {
    let mut result = Array::<u8, L>::default();
    result
        .chunks_mut(<H as Digest>::output_size())
        .enumerate()
        .for_each(|(counter, chunk)| {
            let counter: u32 = counter
                .try_into()
                .expect("L should be less than (2^32 * Digest::output_size) bytes");
            let mut hasher = H::new();
            hasher.update(seed);
            hasher.update(counter.to_be_bytes());
            let result = hasher.finalize();
            chunk.copy_from_slice(&result[..chunk.len()]);
        });
    result
}

/// Implements component hash functions using SHA2 at Security Category 1
/// Follows section 10.2 of FIPS 205
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha2L1<N, M> {
    _n: core::marker::PhantomData<N>,
    _m: core::marker::PhantomData<M>,
}

impl<N: ArraySize, M: ArraySize> HashSuite for Sha2L1<N, M>
where
    N: core::ops::Add<N>,
    Sum<N, N>: ArraySize,
    Sum<N, N>: core::ops::Add<U32>,
    Sum<Sum<N, N>, U32>: ArraySize,
    U64: core::ops::Sub<N>,
    Diff<U64, N>: ArraySize,
    N: Debug + PartialEq + Eq,
    M: Debug + PartialEq + Eq,
{
    type N = N;
    type M = M;

    /// Computes PRF_msg(rand || msg) using HMAC SHA256
    fn prf_msg(
        sk_prf: &SkPrf<Self::N>,
        opt_rand: &Array<u8, Self::N>,
        msg: &[impl AsRef<[u8]>],
    ) -> Array<u8, Self::N> {
        let mut mac = Hmac::<Sha256>::new_from_slice(sk_prf.as_ref()).unwrap();
        mac.update(opt_rand.as_slice());
        for part in msg {
            mac.update(part.as_ref());
        }
        let result = mac.finalize().into_bytes();
        Array::clone_from_slice(&result[..Self::N::USIZE])
    }

    /// Computes H_msg as MGF1 SHA256 over rand || pk_seed || SHA256(rand || pk_seed || pk_root || msg)
    fn h_msg(
        rand: &Array<u8, Self::N>,
        pk_seed: &PkSeed<Self::N>,
        pk_root: &Array<u8, Self::N>,
        msg: &[impl AsRef<[u8]>],
    ) -> Array<u8, Self::M> {
        // H(rand || pk_seed || pk_root || msg...)
        let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + msg.len());
        parts.push(rand.as_slice());
        parts.push(pk_seed.as_ref());
        parts.push(pk_root.as_slice());
        for p in msg {
            parts.push(p.as_ref());
        }
        let digest = sha256_syscall(&parts); // 32 bytes
        let result = Array(digest);

        // seed = rand || pk_seed || result
        let seed = rand.clone().concat(pk_seed.0.clone()).concat(result);
        mgf1::<Sha256, Self::M>(&seed)
    }

    /// Computes PRF_sk as SHA256(pk_seed || zeroPad(64-N) || ADRSc || sk_seed)
    fn prf_sk(
        pk_seed: &PkSeed<Self::N>,
        sk_seed: &SkSeed<Self::N>,
        adrs: &impl Address,
    ) -> Array<u8, Self::N> {
        let zeroes = Array::<u8, Diff<U64, N>>::default();
        let adrs_c = adrs.compressed();
        let hash = sha256_syscall(&[
            pk_seed.as_ref(),
            zeroes.as_slice(),
            adrs_c.as_slice(),
            sk_seed.as_ref(),
        ]);
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    /// Computes T_l as SHA256(pk_seed || zeroPad(64-N) || ADRSc || M[0] .. M[L-1])
    /// Builds parts with Vec to avoid generic const expressions
    fn t<L: ArraySize>(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m: &Array<Array<u8, Self::N>, L>,
    ) -> Array<u8, Self::N> {
        let zeroes = Array::<u8, Diff<U64, N>>::default();
        let adrs_c = adrs.compressed();

        let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + L::USIZE);
        parts.push(pk_seed.as_ref());
        parts.push(zeroes.as_slice());
        parts.push(adrs_c.as_slice());
        for i in 0..L::USIZE {
            parts.push(m[i].as_slice());
        }

        let hash = sha256_syscall(&parts);
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    /// Computes H as SHA256(pk_seed || zeroPad(64-N) || ADRSc || m1 || m2)
    fn h(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m1: &Array<u8, Self::N>,
        m2: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let zeroes = Array::<u8, Diff<U64, N>>::default();
        let adrs_c = adrs.compressed();
        let hash = sha256_syscall(&[
            pk_seed.as_ref(),
            zeroes.as_slice(),
            adrs_c.as_slice(),
            m1.as_slice(),
            m2.as_slice(),
        ]);
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    /// Computes F as SHA256(pk_seed || zeroPad(64-N) || ADRSc || m)
    fn f(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let zeroes = Array::<u8, Diff<U64, N>>::default();
        let adrs_c = adrs.compressed();
        let hash = sha256_syscall(&[
            pk_seed.as_ref(),
            zeroes.as_slice(),
            adrs_c.as_slice(),
            m.as_slice(),
        ]);
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }
}

/// SHA2 at L1 security with small signatures
pub type Sha2_128s = Sha2L1<U16, U30>;
impl WotsParams for Sha2_128s {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Sha2_128s {
    type HPrime = U<9>;
}
impl HypertreeParams for Sha2_128s {
    type D = U<7>;
    type H = U<63>;
}
impl ForsParams for Sha2_128s {
    type K = U<14>;
    type A = U<12>;
    type MD = U<{ (12 * 14 + 7) / 8 }>;
}
impl ParameterSet for Sha2_128s {
    const NAME: &'static str = "SLH-DSA-SHA2-128s";
    /// Uses a provisional OID and replaces it when an official OID exists
    const ALGORITHM_OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.1");
}

/// SHA2 at L1 security with fast signatures
pub type Sha2_128f = Sha2L1<U16, U34>;
impl WotsParams for Sha2_128f {
    type WotsMsgLen = U<32>;
    type WotsSigLen = U<35>;
}
impl XmssParams for Sha2_128f {
    type HPrime = U<3>;
}
impl HypertreeParams for Sha2_128f {
    type D = U<22>;
    type H = U<66>;
}
impl ForsParams for Sha2_128f {
    type K = U<33>;
    type A = U<6>;
    type MD = U<25>;
}
impl ParameterSet for Sha2_128f {
    const NAME: &'static str = "SLH-DSA-SHA2-128f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.2");
}

/// Implements component hash functions using SHA2 at Security Category 3 and 5
/// Follows section 10.2 of FIPS 205
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha2L35<N, M> {
    _n: core::marker::PhantomData<N>,
    _m: core::marker::PhantomData<M>,
}

impl<N: ArraySize, M: ArraySize> HashSuite for Sha2L35<N, M>
where
    N: core::ops::Add<N>,
    Sum<N, N>: ArraySize,
    Sum<N, N>: core::ops::Add<U64>,
    Sum<Sum<N, N>, U64>: ArraySize,
    U64: core::ops::Sub<N>,
    Diff<U64, N>: ArraySize,
    U128: core::ops::Sub<N>,
    Diff<U128, N>: ArraySize,
    N: core::fmt::Debug + PartialEq + Eq,
    M: core::fmt::Debug + PartialEq + Eq,
{
    type N = N;
    type M = M;

    /// Computes PRF_msg(rand || msg) using HMAC SHA512
    fn prf_msg(
        sk_prf: &SkPrf<Self::N>,
        opt_rand: &Array<u8, Self::N>,
        msg: &[impl AsRef<[u8]>],
    ) -> Array<u8, Self::N> {
        let mut mac = Hmac::<Sha512>::new_from_slice(sk_prf.as_ref()).unwrap();
        mac.update(opt_rand.as_slice());
        for part in msg {
            mac.update(part.as_ref());
        }
        let result = mac.finalize().into_bytes();
        Array::clone_from_slice(&result[..Self::N::USIZE])
    }

    /// Computes H_msg as MGF1 SHA512 over rand || pk_seed || SHA512(rand || pk_seed || pk_root || msg)
    fn h_msg(
        rand: &Array<u8, Self::N>,
        pk_seed: &PkSeed<Self::N>,
        pk_root: &Array<u8, Self::N>,
        msg: &[impl AsRef<[u8]>],
    ) -> Array<u8, Self::M> {
        let mut h = Sha512::new();
        h.update(rand);
        h.update(pk_seed);
        h.update(pk_root);
        for p in msg {
            h.update(p.as_ref());
        }
        let result = Array(h.finalize().into()); // 64B
        let seed = rand.clone().concat(pk_seed.0.clone()).concat(result);
        mgf1::<Sha512, Self::M>(&seed)
    }

    /// Computes PRF_sk as SHA256(pk_seed || zeroPad(64-N) || ADRSc || sk_seed)
    /// Uses SHA256 for L3 and L5
    fn prf_sk(
        pk_seed: &PkSeed<Self::N>,
        sk_seed: &SkSeed<Self::N>,
        adrs: &impl Address,
    ) -> Array<u8, Self::N> {
        let zeroes = Array::<u8, Diff<U64, N>>::default();
        let adrs_c = adrs.compressed();
        let hash = sha256_syscall(&[
            pk_seed.as_ref(),
            zeroes.as_slice(),
            adrs_c.as_slice(),
            sk_seed.as_ref(),
        ]);
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    /// Computes T_l as SHA512(pk_seed || zeroPad(128-N) || ADRSc || M[0] .. M[L-1])
    fn t<L: ArraySize>(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m: &Array<Array<u8, Self::N>, L>,
    ) -> Array<u8, Self::N> {
        let zeroes = Array::<u8, Diff<U128, N>>::default();
        let mut sha = Sha512::new()
            .chain_update(pk_seed)
            .chain_update(&zeroes)
            .chain_update(adrs.compressed());
        m.iter().for_each(|x| sha.update(x.as_slice()));
        let hash = sha.finalize();
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    /// Computes H as SHA512(pk_seed || zeroPad(128-N) || ADRSc || m1 || m2)
    fn h(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m1: &Array<u8, Self::N>,
        m2: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let zeroes = Array::<u8, Diff<U128, N>>::default();
        let hash = Sha512::new()
            .chain_update(pk_seed)
            .chain_update(&zeroes)
            .chain_update(adrs.compressed())
            .chain_update(m1)
            .chain_update(m2)
            .finalize();
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }

    /// Computes F as SHA256(pk_seed || zeroPad(64-N) || ADRSc || m)
    /// Uses SHA256 for L3 and L5
    fn f(
        pk_seed: &PkSeed<Self::N>,
        adrs: &impl Address,
        m: &Array<u8, Self::N>,
    ) -> Array<u8, Self::N> {
        let zeroes = Array::<u8, Diff<U64, N>>::default();
        let adrs_c = adrs.compressed();
        let hash = sha256_syscall(&[
            pk_seed.as_ref(),
            zeroes.as_slice(),
            adrs_c.as_slice(),
            m.as_slice(),
        ]);
        Array::clone_from_slice(&hash[..Self::N::USIZE])
    }
}

/// SHA2 at L3 security with small signatures
pub type Sha2_192s = Sha2L35<U24, U39>;
impl WotsParams for Sha2_192s {
    type WotsMsgLen = U<{ 24 * 2 }>;
    type WotsSigLen = U<{ 24 * 2 + 3 }>;
}
impl XmssParams for Sha2_192s {
    type HPrime = U<9>;
}
impl HypertreeParams for Sha2_192s {
    type D = U<7>;
    type H = U<63>;
}
impl ForsParams for Sha2_192s {
    type K = U<17>;
    type A = U<14>;
    type MD = U<{ (14 * 17 + 7) / 8 }>;
}
impl ParameterSet for Sha2_192s {
    const NAME: &'static str = "SLH-DSA-SHA2-192s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.3");
}

/// SHA2 at L3 security with fast signatures
pub type Sha2_192f = Sha2L35<U24, U42>;
impl WotsParams for Sha2_192f {
    type WotsMsgLen = U<{ 24 * 2 }>;
    type WotsSigLen = U<{ 24 * 2 + 3 }>;
}
impl XmssParams for Sha2_192f {
    type HPrime = U<3>;
}
impl HypertreeParams for Sha2_192f {
    type D = U<22>;
    type H = U<66>;
}
impl ForsParams for Sha2_192f {
    type K = U<33>;
    type A = U<8>;
    type MD = U<{ (33 * 8 + 7) / 8 }>;
}
impl ParameterSet for Sha2_192f {
    const NAME: &'static str = "SLH-DSA-SHA2-192f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.4");
}

/// SHA2 at L5 security with small signatures
pub type Sha2_256s = Sha2L35<U32, U47>;
impl WotsParams for Sha2_256s {
    type WotsMsgLen = U<{ 32 * 2 }>;
    type WotsSigLen = U<{ 32 * 2 + 3 }>;
}
impl XmssParams for Sha2_256s {
    type HPrime = U<8>;
}
impl HypertreeParams for Sha2_256s {
    type D = U<8>;
    type H = U<64>;
}
impl ForsParams for Sha2_256s {
    type K = U<22>;
    type A = U<14>;
    type MD = U<{ (14 * 22 + 7) / 8 }>;
}
impl ParameterSet for Sha2_256s {
    const NAME: &'static str = "SLH-DSA-SHA2-256s";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.5");
}

/// SHA2 at L5 security with fast signatures
pub type Sha2_256f = Sha2L35<U32, U49>;
impl WotsParams for Sha2_256f {
    type WotsMsgLen = U<{ 32 * 2 }>;
    type WotsSigLen = U<{ 32 * 2 + 3 }>;
}
impl XmssParams for Sha2_256f {
    type HPrime = U<4>;
}
impl HypertreeParams for Sha2_256f {
    type D = U<17>;
    type H = U<68>;
}
impl ForsParams for Sha2_256f {
    type K = U<35>;
    type A = U<9>;
    type MD = U<{ (35 * 9 + 7) / 8 }>;
}
impl ParameterSet for Sha2_256f {
    const NAME: &'static str = "SLH-DSA-SHA2-256f";
    const ALGORITHM_OID: pkcs8::ObjectIdentifier =
        pkcs8::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1.6");
}
