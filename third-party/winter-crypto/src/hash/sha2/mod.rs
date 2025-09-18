#![allow(clippy::needless_lifetimes)]

use core::marker::PhantomData;
#[cfg(any(target_arch = "bpf", target_os = "solana"))]
use alloc::vec::Vec;

use math::{FieldElement, StarkField};
use utils::ByteWriter;

use super::{ByteDigest, ElementHasher, Hasher};
use super::Digest as _;

/// Implements SHA256 with 256 bit output.
/// On Solana BPF it uses solana_program::hash::hashv.
/// Off chain it uses sha2::Sha256.
pub struct Sha2_256<B: StarkField>(PhantomData<B>);

impl<B: StarkField> Hasher for Sha2_256<B> {
    type Digest = ByteDigest<32>;
    const COLLISION_RESISTANCE: u32 = 128;

    #[inline]
    fn hash(bytes: &[u8]) -> Self::Digest {
        ByteDigest(sha256_once(bytes))
    }

    #[inline]
    fn merge(values: &[Self::Digest; 2]) -> Self::Digest {
        ByteDigest(sha256_once(ByteDigest::digests_as_bytes(values)))
    }

    #[inline]
    fn merge_many(values: &[Self::Digest]) -> Self::Digest {
        ByteDigest(sha256_once(ByteDigest::digests_as_bytes(values)))
    }

    #[inline]
    fn merge_with_int(seed: Self::Digest, value: u64) -> Self::Digest {
        let mut data = [0u8; 40];
        data[..32].copy_from_slice(&seed.as_bytes());
        data[32..].copy_from_slice(&value.to_le_bytes());
        ByteDigest(sha256_once(&data))
    }
}

impl<B: StarkField> ElementHasher for Sha2_256<B> {
    type BaseField = B;

    #[inline]
    fn hash_elements<E: FieldElement<BaseField = Self::BaseField>>(elements: &[E]) -> Self::Digest {
        if B::IS_CANONICAL {
            let bytes = E::elements_as_bytes(elements);
            ByteDigest(sha256_once(bytes))
        } else {
            let mut w = Sha256Writer::new();
            w.write_many(elements);
            ByteDigest(w.finalize())
        }
    }
}

/// Computes a single SHA256 digest based on the compilation target
#[inline]
fn sha256_once(bytes: &[u8]) -> [u8; 32] {
    #[cfg(any(target_arch = "bpf", target_os = "solana"))]
    {
        use solana_program::hash::hashv;
        hashv(&[bytes]).to_bytes()
    }
    #[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
    {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }
}

/// Wraps byte writing for element hashing.
/// On host it streams into sha2.
/// On BPF it buffers and hashes once to reduce syscalls.
struct Sha256Writer {
    #[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
    inner: sha2::Sha256,
    #[cfg(any(target_arch = "bpf", target_os = "solana"))]
    buf: Vec<u8>,
}

impl Sha256Writer {
    fn new() -> Self {
        #[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
        {
            use sha2::Digest;
            Self { inner: sha2::Sha256::new() }
        }
        #[cfg(any(target_arch = "bpf", target_os = "solana"))]
        {
            Self { buf: Vec::new() }
        }
    }

    fn finalize(self) -> [u8; 32] {
        #[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
        {
            use sha2::Digest;
            self.inner.finalize().into()
        }
        #[cfg(any(target_arch = "bpf", target_os = "solana"))]
        {
            sha256_once(&self.buf)
        }
    }
}

impl ByteWriter for Sha256Writer {
    #[inline]
    fn write_u8(&mut self, value: u8) {
        #[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
        {
            use sha2::Digest;
            self.inner.update(&[value]);
        }
        #[cfg(any(target_arch = "bpf", target_os = "solana"))]
        {
            self.buf.push(value);
        }
    }

    #[inline]
    fn write_bytes(&mut self, values: &[u8]) {
        #[cfg(not(any(target_arch = "bpf", target_os = "solana")))]
        {
            use sha2::Digest;
            self.inner.update(values);
        }
        #[cfg(any(target_arch = "bpf", target_os = "solana"))]
        {
            self.buf.extend_from_slice(values);
        }
    }
}
