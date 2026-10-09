//! Targeted hardware acceleration and portable SIMD routines for GF(2^8) Reed-Solomon math.
//!
//! Phase 17 specification:
//! - Targeted vectorization for Galois field polynomial multiplication and XOR parity generation.
//! - Strict `#![forbid(unsafe_code)]` in the Rust substrate: uses compiler auto-vectorization
//!   friendly unrolled chunk slices with zero unsafe pointers.
//! - Pluggable backend descriptor allowing dynamic or static linkage with Zig, C, AVX-512,
//!   or CUDA acceleration libraries when available on target platforms.

#![forbid(unsafe_code)]

use crate::gf_mul;

/// Hardware acceleration backend mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HwEngineKind {
    /// Pure scalar baseline.
    Scalar,
    /// Chunk-unrolled portable SIMD optimization (128-bit/64-bit lane unrolling).
    PortableSimd,
    /// Hardware AVX2 / AVX-512 targeted vectorization.
    AvxTargeted,
    /// External C / Zig / CUDA foreign acceleration library.
    ForeignAccel,
}

/// Acceleration interface for high-throughput batch operations over GF(2^8).
pub struct HwAccelEngine;

impl HwAccelEngine {
    /// In-place vector XOR: `dst[i] ^= src[i]` using 64-bit unrolled chunks.
    #[inline]
    pub fn vector_xor(dst: &mut [u8], src: &[u8]) {
        assert_eq!(dst.len(), src.len(), "vector lengths must match");

        let mut chunks_dst = dst.chunks_exact_mut(8);
        let mut chunks_src = src.chunks_exact(8);

        for (d_chunk, s_chunk) in chunks_dst.by_ref().zip(chunks_src.by_ref()) {
            let d_val = u64::from_ne_bytes(d_chunk.try_into().unwrap());
            let s_val = u64::from_ne_bytes(s_chunk.try_into().unwrap());
            d_chunk.copy_from_slice(&(d_val ^ s_val).to_ne_bytes());
        }

        let rem_dst = chunks_dst.into_remainder();
        let rem_src = chunks_src.remainder();
        for (d, s) in rem_dst.iter_mut().zip(rem_src.iter()) {
            *d ^= *s;
        }
    }

    /// Multiply a slice of GF(2^8) bytes by a constant scalar `factor`.
    #[inline]
    pub fn vector_gf_mul(slice: &mut [u8], factor: u8) {
        if factor == 0 {
            slice.fill(0);
            return;
        }
        if factor == 1 {
            return;
        }

        // Process in 4-byte unrolled loop for instruction-level parallelism
        let mut chunks = slice.chunks_exact_mut(4);
        for chunk in chunks.by_ref() {
            chunk[0] = gf_mul(chunk[0], factor);
            chunk[1] = gf_mul(chunk[1], factor);
            chunk[2] = gf_mul(chunk[2], factor);
            chunk[3] = gf_mul(chunk[3], factor);
        }

        let rem = chunks.into_remainder();
        for b in rem.iter_mut() {
            *b = gf_mul(*b, factor);
        }
    }

    /// Multiply `src` by `factor` and accumulate (XOR) into `dst`: `dst[i] ^= gf_mul(src[i], factor)`.
    #[inline]
    pub fn vector_gf_mul_acc(dst: &mut [u8], src: &[u8], factor: u8) {
        assert_eq!(dst.len(), src.len(), "vector lengths must match");
        if factor == 0 {
            return;
        }

        let mut chunks_dst = dst.chunks_exact_mut(4);
        let mut chunks_src = src.chunks_exact(4);

        for (d, s) in chunks_dst.by_ref().zip(chunks_src.by_ref()) {
            d[0] ^= gf_mul(s[0], factor);
            d[1] ^= gf_mul(s[1], factor);
            d[2] ^= gf_mul(s[2], factor);
            d[3] ^= gf_mul(s[3], factor);
        }

        let rem_dst = chunks_dst.into_remainder();
        let rem_src = chunks_src.remainder();
        for (d, s) in rem_dst.iter_mut().zip(rem_src.iter()) {
            *d ^= gf_mul(*s, factor);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_xor_equivalence() {
        let mut dst = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22];
        let src = vec![0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x33, 0x44];
        let mut expected = dst.clone();
        for (e, s) in expected.iter_mut().zip(src.iter()) {
            *e ^= *s;
        }

        HwAccelEngine::vector_xor(&mut dst, &src);
        assert_eq!(dst, expected);
    }

    #[test]
    fn vector_gf_mul_correctness() {
        let mut data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let factor = 7;
        let expected: Vec<u8> = data.iter().map(|&x| gf_mul(x, factor)).collect();

        HwAccelEngine::vector_gf_mul(&mut data, factor);
        assert_eq!(data, expected);
    }

    #[test]
    fn vector_gf_mul_acc_correctness() {
        let mut dst = vec![10, 20, 30, 40, 50];
        let src = vec![1, 2, 3, 4, 5];
        let factor = 3;
        let mut expected = dst.clone();
        for (d, s) in expected.iter_mut().zip(src.iter()) {
            *d ^= gf_mul(*s, factor);
        }

        HwAccelEngine::vector_gf_mul_acc(&mut dst, &src, factor);
        assert_eq!(dst, expected);
    }
}
