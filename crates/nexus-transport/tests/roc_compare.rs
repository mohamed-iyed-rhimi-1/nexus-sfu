//! Compare ROC estimation between our algorithm and webrtc-rs's algorithm
//! for sequential packets. Find any divergence.

/// Our ROC estimation (RFC 3711 Appendix A)
fn nexus_estimate_roc(s_l: u16, roc: u32, seq: u16, initialized: bool) -> u32 {
    if !initialized {
        return 0;
    }
    if s_l < 32768 {
        if seq.wrapping_sub(s_l) > 32768 {
            if roc > 0 { roc - 1 } else { 0 }
        } else {
            roc
        }
    } else {
        if s_l - 32768 > seq {
            roc + 1
        } else {
            roc
        }
    }
}

/// Our ROC update
fn nexus_update(s_l: &mut u16, roc: &mut u32, seq: u16, initialized: &mut bool) {
    if !*initialized {
        *s_l = seq;
        *initialized = true;
        return;
    }
    let old_s_l = *s_l;
    if old_s_l < 32768 {
        if seq.wrapping_sub(old_s_l) <= 32768 && seq > old_s_l {
            *s_l = seq;
        }
    } else {
        if old_s_l - 32768 > seq {
            *roc += 1;
            *s_l = seq;
        } else if seq > old_s_l {
            *s_l = seq;
        }
    }
}

const MAX_ROC_DISORDER: u16 = 100;
const MAX_SEQUENCE_NUMBER: u16 = 65535;

/// webrtc-rs ROC estimation
fn webrtc_estimate_roc(last_seq: u16, roc: u32, seq: u16, processed: bool) -> u32 {
    if !processed {
        return roc;
    }
    if seq == 0 {
        if last_seq > MAX_ROC_DISORDER {
            roc + 1
        } else {
            roc
        }
    } else if last_seq < MAX_ROC_DISORDER
        && seq > (MAX_SEQUENCE_NUMBER - MAX_ROC_DISORDER)
    {
        if roc > 0 { roc - 1 } else { 0 }
    } else if seq < MAX_ROC_DISORDER
        && last_seq > (MAX_SEQUENCE_NUMBER - MAX_ROC_DISORDER)
    {
        roc + 1
    } else {
        roc
    }
}

/// webrtc-rs ROC update
fn webrtc_update(last_seq: &mut u16, roc: &mut u32, seq: u16, processed: &mut bool) {
    if !*processed {
        *processed = true;
    } else if seq == 0 {
        if *last_seq > MAX_ROC_DISORDER {
            *roc += 1;
        }
    } else if *last_seq < MAX_ROC_DISORDER
        && seq > (MAX_SEQUENCE_NUMBER - MAX_ROC_DISORDER)
    {
        *roc -= 1;
    } else if seq < MAX_ROC_DISORDER
        && *last_seq > (MAX_SEQUENCE_NUMBER - MAX_ROC_DISORDER)
    {
        *roc += 1;
    }
    *last_seq = seq;
}

#[test]
fn find_roc_divergence_sequential() {
    // Try many starting sequence numbers
    for start_seq in (0u32..65536).step_by(1000) {
        let start = start_seq as u16;

        // Nexus state
        let mut n_sl: u16 = 0;
        let mut n_roc: u32 = 0;
        let mut n_init = false;

        // webrtc-rs state
        let mut w_last: u16 = 0;
        let mut w_roc: u32 = 0;
        let mut w_proc = false;

        // Send 200,000 sequential packets (covers ~3 full wraps)
        for i in 0u32..200_000 {
            let seq = start.wrapping_add(i as u16);

            let n_est = nexus_estimate_roc(n_sl, n_roc, seq, n_init);
            let w_est = webrtc_estimate_roc(w_last, w_roc, seq, w_proc);

            if n_est != w_est {
                panic!(
                    "DIVERGENCE at start={start}, i={i}, seq={seq}: \
                     nexus_roc={n_est} (s_l={n_sl}, roc={n_roc}) vs \
                     webrtc_roc={w_est} (last={w_last}, roc={w_roc})"
                );
            }

            nexus_update(&mut n_sl, &mut n_roc, seq, &mut n_init);
            webrtc_update(&mut w_last, &mut w_roc, seq, &mut w_proc);

            // Also verify state stays in sync
            if n_roc != w_roc {
                panic!(
                    "STATE DIVERGENCE at start={start}, i={i}, seq={seq}: \
                     nexus_roc={n_roc} vs webrtc_roc={w_roc}"
                );
            }
        }
    }
    eprintln!("All starting sequences tested — no divergence found for sequential packets");
}
