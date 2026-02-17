//! Batch RTP packet parsing with SIMD prefetch optimization.
//!
//! These methods process multiple RTP packets in a batch, matching
//! the I/O batch size of 64 packets (from transport batch sender).
//!
//! All batch methods write into a caller-provided output slice —
//! zero allocation on the hot path.

use super::header::RtpHeader;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

impl RtpHeader {
    /// Parse a batch of RTP packets using the optimal
    /// CPU-specific implementation.
    ///
    /// Writes results into `out`. Returns the number of entries
    /// written (always `min(packets.len(), out.len())`).
    #[inline]
    pub fn parse_batch_optimal(
        packets: &[&[u8]],
        out: &mut [Option<Self>],
    ) -> usize {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") {
                return Self::parse_batch_avx512_impl(packets, out);
            }
            if is_x86_feature_detected!("avx2") {
                return Self::parse_batch_avx2_impl(packets, out);
            }
        }

        Self::parse_batch_scalar(packets, out)
    }

    /// Parse a batch of RTP packets using scalar parsing with
    /// prefetch optimization.
    #[inline]
    pub fn parse_batch_scalar(
        packets: &[&[u8]],
        out: &mut [Option<Self>],
    ) -> usize {
        let count = packets.len().min(out.len());
        let prefetch_distance = 4;

        for i in 0..count {
            if i + prefetch_distance < packets.len() {
                let prefetch_ptr =
                    packets[i + prefetch_distance].as_ptr();
                #[cfg(target_arch = "x86_64")]
                {
                    if is_x86_feature_detected!("sse") {
                        unsafe {
                            _mm_prefetch(
                                prefetch_ptr as *const i8,
                                _MM_HINT_T0,
                            );
                        }
                    }
                }
                #[cfg(target_arch = "aarch64")]
                {
                    unsafe {
                        std::arch::asm!(
                            "prfm pldl1keep, [{ptr}]",
                            ptr = in(reg) prefetch_ptr,
                            options(nostack, preserves_flags)
                        );
                    }
                }
                #[cfg(not(any(
                    target_arch = "x86_64",
                    target_arch = "aarch64"
                )))]
                let _ = prefetch_ptr;
            }

            out[i] = Self::parse(packets[i]).ok();
        }

        count
    }

    /// Parse a batch using AVX2-optimized chunking.
    #[inline]
    pub fn parse_batch_avx2(
        packets: &[&[u8]],
        out: &mut [Option<Self>],
    ) -> usize {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                return Self::parse_batch_avx2_impl(packets, out);
            }
        }
        Self::parse_batch_scalar(packets, out)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn parse_batch_avx2_impl(
        packets: &[&[u8]],
        out: &mut [Option<Self>],
    ) -> usize {
        const CHUNK_SIZE: usize = 8;
        let count = packets.len().min(out.len());
        let mut written = 0;

        let chunks = packets[..count].chunks(CHUNK_SIZE);
        let mut chunks_peekable = chunks.peekable();

        while let Some(chunk) = chunks_peekable.next() {
            if let Some(next_chunk) = chunks_peekable.peek() {
                for packet in next_chunk.iter() {
                    unsafe {
                        _mm_prefetch(
                            packet.as_ptr() as *const i8,
                            _MM_HINT_T0,
                        );
                    }
                }
            }

            for packet in chunk {
                out[written] = Self::parse_simd(packet);
                written += 1;
            }
        }

        written
    }

    /// Parse a batch using AVX-512-optimized chunking.
    #[inline]
    pub fn parse_batch_avx512(
        packets: &[&[u8]],
        out: &mut [Option<Self>],
    ) -> usize {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx512f") {
                return Self::parse_batch_avx512_impl(packets, out);
            }
        }
        Self::parse_batch_scalar(packets, out)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn parse_batch_avx512_impl(
        packets: &[&[u8]],
        out: &mut [Option<Self>],
    ) -> usize {
        const CHUNK_SIZE: usize = 16;
        let count = packets.len().min(out.len());
        let mut written = 0;

        let chunks = packets[..count].chunks(CHUNK_SIZE);
        let mut chunks_peekable = chunks.peekable();

        while let Some(chunk) = chunks_peekable.next() {
            if let Some(next_chunk) = chunks_peekable.peek() {
                for packet in next_chunk.iter() {
                    unsafe {
                        _mm_prefetch(
                            packet.as_ptr() as *const i8,
                            _MM_HINT_T0,
                        );
                    }
                }
            }

            for packet in chunk {
                out[written] = Self::parse_simd(packet);
                written += 1;
            }
        }

        written
    }
}
