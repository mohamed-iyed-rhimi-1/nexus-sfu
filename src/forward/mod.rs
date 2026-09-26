//! SSRC routing for the ingress loop.
//!
//! `SsrcRouter` maps an incoming packet's SSRC to its track and the worker
//! that owns it: `routes: DashMap<SSRC, (TrackId, WorkerId)>`.

mod router;

pub use router::{SsrcError, SsrcRouter};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify module exports are accessible
        let _ = SsrcRouter::new();
    }
}
