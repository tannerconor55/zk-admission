use crate::error::ProtocolError;

/// Maximum V1 sequence-window width.
pub const WINDOW_MAX: u32 = 1024;

/// Half-open sequence window:
/// [seq_start, seq_end_exclusive)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequenceWindowV1 {
    pub seq_start: u32,
    pub seq_end_exclusive: u32,
}

impl SequenceWindowV1 {
    pub fn new(seq_start: u32, seq_end_exclusive: u32) -> Result<Self, ProtocolError> {
        if seq_start >= seq_end_exclusive {
            return Err(ProtocolError::InvalidSequenceWindow);
        }

        let window_len = seq_end_exclusive
            .checked_sub(seq_start)
            .ok_or(ProtocolError::SequenceArithmetic)?;

        if window_len > WINDOW_MAX {
            return Err(ProtocolError::WindowTooLarge);
        }

        Ok(Self {
            seq_start,
            seq_end_exclusive,
        })
    }

    pub fn contains(&self, sequence: u32) -> bool {
        sequence >= self.seq_start && sequence < self.seq_end_exclusive
    }

    /// Number of prior positions in [seq_start, candidate_seq).
    ///
    /// Zero means candidate_seq == seq_start.
    ///
    /// The Holochain activity query must not be invoked with take(0).
    pub fn prior_len(&self, candidate_seq: u32) -> Result<u32, ProtocolError> {
        candidate_seq
            .checked_sub(self.seq_start)
            .ok_or(ProtocolError::SequenceArithmetic)
    }

    pub fn window_len(&self) -> Result<u32, ProtocolError> {
        self.seq_end_exclusive
            .checked_sub(self.seq_start)
            .ok_or(ProtocolError::SequenceArithmetic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_open_window() {
        let window = SequenceWindowV1::new(7, 10).unwrap();

        assert!(!window.contains(6));
        assert!(window.contains(7));
        assert!(window.contains(8));
        assert!(window.contains(9));
        assert!(!window.contains(10));
    }

    #[test]
    fn prior_length() {
        let window = SequenceWindowV1::new(7, 10).unwrap();

        assert_eq!(window.prior_len(7).unwrap(), 0);
        assert_eq!(window.prior_len(8).unwrap(), 1);
        assert_eq!(window.prior_len(9).unwrap(), 2);
        assert_eq!(window.prior_len(10).unwrap(), 3);
    }

    #[test]
    fn candidate_before_window_is_rejected() {
        let window = SequenceWindowV1::new(7, 10).unwrap();

        assert_eq!(window.prior_len(6), Err(ProtocolError::SequenceArithmetic));
    }

    #[test]
    fn oversized_window_is_rejected() {
        assert_eq!(
            SequenceWindowV1::new(0, WINDOW_MAX + 1),
            Err(ProtocolError::WindowTooLarge)
        );
    }

    #[test]
    fn reversed_window_is_rejected() {
        assert_eq!(
            SequenceWindowV1::new(10, 7),
            Err(ProtocolError::InvalidSequenceWindow)
        );
    }
}
