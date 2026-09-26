//! RFC 3711 packet index estimation (Appendix A, §3.3.1).
//!
//! One place for the rollover-counter logic, used by `SrtpContext` and the
//! per-direction contexts (`SrtpInbound`, `SrtpOutbound`).

use super::error::SrtpError;
use super::types::PacketIndex;

/// Rollover counter and highest sequence number of one SSRC.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RocState {
    roc: u32,
    highest_seq: u16,
    initialized: bool,
}

impl RocState {
    /// State before the first packet of an SSRC.
    pub(crate) const fn new() -> Self {
        Self {
            roc: 0,
            highest_seq: 0,
            initialized: false,
        }
    }

    /// State at a given ROC and highest sequence number (tests).
    #[cfg(test)]
    pub(crate) const fn at(roc: u32, highest_seq: u16) -> Self {
        Self {
            roc,
            highest_seq,
            initialized: true,
        }
    }

    pub(crate) const fn roc(&self) -> u32 {
        self.roc
    }

    pub(crate) const fn highest_seq(&self) -> u16 {
        self.highest_seq
    }

    #[cfg(test)]
    pub(crate) const fn initialized(&self) -> bool {
        self.initialized
    }

    /// Estimates the packet index of `seq` (RFC 3711 Appendix A).
    ///
    /// Returns `Err(SrtpError::RocOverflow)` if the rollover counter would
    /// exceed `u32::MAX`: the SRTP context must be renegotiated (§3.3.1).
    pub(crate) fn estimate_index(&self, seq: u16) -> Result<PacketIndex, SrtpError> {
        if !self.initialized {
            return Ok(PacketIndex::new(0, seq));
        }

        let s_l = self.highest_seq;
        let roc = self.roc;

        if s_l < 32768 {
            // RFC 3711 Appendix A: `SEQ - s_l > 2^15` in signed arithmetic.
            // A wrapping subtraction would put every reordered packet
            // (seq < s_l) into the previous ROC.
            if seq > s_l && seq - s_l > 32768 {
                // From the previous ROC; before the first ROC it stays 0.
                Ok(PacketIndex::new(roc.saturating_sub(1), seq))
            } else {
                Ok(PacketIndex::new(roc, seq))
            }
        } else if s_l - 32768 > seq {
            // s_l >= 32768: check if s_l - 32768 > seq (NOT wrapping_sub)
            if roc == u32::MAX {
                return Err(SrtpError::RocOverflow);
            }
            Ok(PacketIndex::new(roc + 1, seq))
        } else {
            Ok(PacketIndex::new(roc, seq))
        }
    }

    /// Updates ROC and highest sequence number after a packet with `seq` was
    /// authenticated (receive side) or protected (send side), §3.3.1.
    ///
    /// Returns `Err(SrtpError::RocOverflow)` if the rollover counter would
    /// exceed `u32::MAX`; the state is then unchanged.
    pub(crate) fn update(&mut self, seq: u16) -> Result<(), SrtpError> {
        if !self.initialized {
            self.highest_seq = seq;
            self.initialized = true;
            return Ok(());
        }

        let s_l = self.highest_seq;

        if s_l < 32768 {
            if seq.wrapping_sub(s_l) <= 32768 && seq > s_l {
                self.highest_seq = seq;
            }
        } else if s_l - 32768 > seq {
            // Wrap detected
            if self.roc == u32::MAX {
                return Err(SrtpError::RocOverflow);
            }
            self.roc += 1;
            self.highest_seq = seq;
        } else if seq > s_l {
            self.highest_seq = seq;
        }
        debug_assert!(self.initialized);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_has_roc_zero() {
        let state = RocState::new();
        for seq in [0u16, 1, 32768, 65535] {
            assert_eq!(state.estimate_index(seq), Ok(PacketIndex::new(0, seq)));
        }
    }

    #[test]
    fn wraps_forward() {
        let mut state = RocState::new();
        state.update(65_500).unwrap();
        assert_eq!(state.estimate_index(5), Ok(PacketIndex::new(1, 5)));
        state.update(5).unwrap();
        assert_eq!((state.roc(), state.highest_seq()), (1, 5));
    }

    #[test]
    fn late_packet_from_previous_roc() {
        let mut state = RocState::at(1, 5);
        assert_eq!(
            state.estimate_index(65_530),
            Ok(PacketIndex::new(0, 65_530))
        );
        // A late packet does not move the state back.
        state.update(65_530).unwrap();
        assert_eq!((state.roc(), state.highest_seq()), (1, 5));
    }

    #[test]
    fn roc_overflow_is_an_error() {
        let mut state = RocState::at(u32::MAX, 40_000);
        assert_eq!(state.estimate_index(100), Err(SrtpError::RocOverflow));
        assert_eq!(state.update(100), Err(SrtpError::RocOverflow));
        assert_eq!(state, RocState::at(u32::MAX, 40_000));
    }

    /// Regression: with ROC > 0 and s_l < 2^15, a packet just below s_l is
    /// from the current ROC (a wrapping subtraction used to say ROC - 1).
    #[test]
    fn reordering_after_a_wrap_keeps_the_roc() {
        let mut state = RocState::at(1, 2);
        assert_eq!(state.estimate_index(1), Ok(PacketIndex::new(1, 1)));
        state.update(1).unwrap();
        assert_eq!((state.roc(), state.highest_seq()), (1, 2));
        assert_eq!(
            state.estimate_index(65_000),
            Ok(PacketIndex::new(0, 65_000))
        );
    }

    #[test]
    fn reordering_within_roc() {
        let mut state = RocState::new();
        state.update(10).unwrap();
        state.update(12).unwrap();
        state.update(11).unwrap();
        assert_eq!(state.highest_seq(), 12);
        assert_eq!(state.estimate_index(11), Ok(PacketIndex::new(0, 11)));
    }
}
