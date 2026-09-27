//! Synthetic media generation
//!
//! Generates test patterns for video and audio to be published
//! by broadcaster and participant clients.

/// Video test pattern type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VideoPattern {
    /// Solid color bars that change over time
    ColorBars,
    /// Moving gradient pattern
    Gradient,
    /// Frame counter overlay
    Counter,
}

impl Default for VideoPattern {
    fn default() -> Self {
        Self::ColorBars
    }
}

/// Audio test pattern type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AudioPattern {
    /// Sine wave at fixed frequency (Hz)
    Tone(u32),
    /// Silence
    Silence,
    /// White noise
    Noise,
}

impl Default for AudioPattern {
    fn default() -> Self {
        Self::Tone(440) // A4 note
    }
}

/// Bytes of the payload marker at the start of every published frame or sample.
pub const MARKER_LEN: usize = 8;

/// Write the payload marker, the publisher's SSRC then a frame counter (both
/// big-endian), over the first `MARKER_LEN` bytes of `data`. A receiver reads them
/// back with [`read_marker`] to check the payload arrived unchanged and from whom.
/// Returns `false` (and writes nothing) when `data` is too short.
pub fn stamp_marker(data: &mut [u8], ssrc: u32, frame: u32) -> bool {
    if data.len() < MARKER_LEN {
        return false;
    }
    data[..4].copy_from_slice(&ssrc.to_be_bytes());
    data[4..MARKER_LEN].copy_from_slice(&frame.to_be_bytes());
    true
}

/// The marker `(ssrc, frame)` of a received RTP payload, when the packet carries one.
///
/// Audio (Opus): one sample per packet, the marker is the payload's first bytes.
/// Video (VP8, RFC 7741 §4.2): a frame is split over packets and only the one that
/// starts it carries the marker, after the payload descriptor.
pub fn read_marker(video: bool, payload: &[u8]) -> Option<(u32, u32)> {
    let start = if video { vp8_frame_start(payload)? } else { 0 };
    let marker = payload.get(start..start + MARKER_LEN)?;
    let ssrc = u32::from_be_bytes([marker[0], marker[1], marker[2], marker[3]]);
    let frame = u32::from_be_bytes([marker[4], marker[5], marker[6], marker[7]]);
    Some((ssrc, frame))
}

/// Offset of the frame data in a VP8 RTP payload that starts a frame (S bit set,
/// partition 0), `None` for any other packet or a truncated descriptor.
fn vp8_frame_start(payload: &[u8]) -> Option<usize> {
    let first = *payload.first()?;
    let (extended, start, partition) = (first & 0x80 != 0, first & 0x10 != 0, first & 0x0F);
    if !start || partition != 0 {
        return None;
    }
    if !extended {
        return Some(1);
    }
    let x = *payload.get(1)?;
    let (has_picture_id, has_tl0, has_tid_or_key) = (x & 0x80 != 0, x & 0x40 != 0, x & 0x30 != 0);
    let mut len = 2;
    if has_picture_id {
        // M bit: 15-bit picture id in two bytes, else 7 bits in one.
        len += if *payload.get(len)? & 0x80 != 0 { 2 } else { 1 };
    }
    if has_tl0 {
        len += 1;
    }
    if has_tid_or_key {
        len += 1;
    }
    (len <= payload.len()).then_some(len)
}

/// Video frame data
pub struct VideoFrame {
    /// Frame width in pixels
    pub width: u32,
    /// Frame height in pixels
    pub height: u32,
    /// Frame data (I420 format)
    pub data: Vec<u8>,
    /// Frame timestamp in microseconds
    pub timestamp_us: u64,
}

/// Synthetic video frame generator
pub struct VideoGenerator {
    /// Frame width
    width: u32,
    /// Frame height
    height: u32,
    /// Frames per second
    fps: u32,
    /// Test pattern type
    pattern: VideoPattern,
    /// Frame counter
    frame_count: u64,
}

impl VideoGenerator {
    /// Create a new video generator
    pub fn new(width: u32, height: u32, fps: u32, pattern: VideoPattern) -> Self {
        Self {
            width,
            height,
            fps,
            pattern,
            frame_count: 0,
        }
    }

    /// Generate next video frame
    pub fn next_frame(&mut self) -> VideoFrame {
        let timestamp_us = (self.frame_count * 1_000_000) / self.fps as u64;
        self.frame_count += 1;

        // Generate I420 frame data
        let y_size = (self.width * self.height) as usize;
        let uv_size = y_size / 4;
        let mut data = vec![0u8; y_size + uv_size * 2];

        match self.pattern {
            VideoPattern::ColorBars => {
                // Simple color bars pattern
                self.generate_color_bars(&mut data);
            }
            VideoPattern::Gradient => {
                // Moving gradient
                self.generate_gradient(&mut data);
            }
            VideoPattern::Counter => {
                // Frame counter (just solid gray with different intensity)
                let intensity = (self.frame_count % 256) as u8;
                data[..y_size].fill(intensity);
                data[y_size..].fill(128); // Neutral UV
            }
        }

        VideoFrame {
            width: self.width,
            height: self.height,
            data,
            timestamp_us,
        }
    }

    /// Next frame sized like encoded video at `bitrate_bps`, for publishing.
    ///
    /// Raw I420 frames are ~50× larger than a real encoder's output at this
    /// resolution, so sending them as VP8 overdrives the SFU with packets. The
    /// payload is a prefix of the pattern frame; every `KEYFRAME_INTERVAL_SECS`
    /// a keyframe is `KEYFRAME_SIZE_FACTOR`× larger, like a real stream.
    pub fn next_encoded_frame(&mut self, bitrate_bps: u32) -> VideoFrame {
        const KEYFRAME_INTERVAL_SECS: u64 = 2;
        const KEYFRAME_SIZE_FACTOR: usize = 4;
        assert!(bitrate_bps > 0, "bitrate must be positive");

        let is_keyframe = self.frame_count % (KEYFRAME_INTERVAL_SECS * self.fps as u64) == 0;
        let mut frame = self.next_frame();
        let delta_bytes = (bitrate_bps as usize / 8 / self.fps as usize).max(1);
        let target = if is_keyframe {
            delta_bytes * KEYFRAME_SIZE_FACTOR
        } else {
            delta_bytes
        };
        frame.data.truncate(target.min(frame.data.len()));
        frame
    }

    fn generate_color_bars(&self, data: &mut [u8]) {
        let y_size = (self.width * self.height) as usize;
        let bar_width = self.width / 8;

        // Y plane - 8 bars with different luminance
        let y_values = [235, 210, 170, 145, 107, 82, 41, 16];
        for y in 0..self.height {
            for x in 0..self.width {
                let bar_idx = (x / bar_width).min(7) as usize;
                data[(y * self.width + x) as usize] = y_values[bar_idx];
            }
        }

        // UV planes - neutral gray
        data[y_size..].fill(128);
    }

    fn generate_gradient(&self, data: &mut [u8]) {
        let y_size = (self.width * self.height) as usize;
        let offset = (self.frame_count % self.width as u64) as u32;

        // Y plane - horizontal gradient with animation
        for y in 0..self.height {
            for x in 0..self.width {
                let val = ((x + offset) % self.width) * 255 / self.width;
                data[(y * self.width + x) as usize] = val as u8;
            }
        }

        // UV planes - neutral gray
        data[y_size..].fill(128);
    }

    /// Get the frame rate
    pub fn fps(&self) -> u32 {
        self.fps
    }

    /// Get the frame dimensions
    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

/// Synthetic audio sample generator
pub struct AudioGenerator {
    /// Sample rate in Hz
    sample_rate: u32,
    /// Number of channels
    channels: u8,
    /// Test pattern type
    pattern: AudioPattern,
    /// Sample counter for phase tracking
    sample_count: u64,
}

impl AudioGenerator {
    /// Create a new audio generator
    pub fn new(sample_rate: u32, channels: u8, pattern: AudioPattern) -> Self {
        Self {
            sample_rate,
            channels,
            pattern,
            sample_count: 0,
        }
    }

    /// Generate next audio samples
    pub fn next_samples(&mut self, count: usize) -> Vec<i16> {
        let total_samples = count * self.channels as usize;
        let mut samples = vec![0i16; total_samples];

        match self.pattern {
            AudioPattern::Tone(freq) => {
                let phase_increment =
                    2.0 * std::f64::consts::PI * freq as f64 / self.sample_rate as f64;

                for i in 0..count {
                    let phase = (self.sample_count + i as u64) as f64 * phase_increment;
                    let sample = (phase.sin() * 16384.0) as i16; // -16384 to 16384 range

                    // Fill all channels with the same sample
                    for ch in 0..self.channels as usize {
                        samples[i * self.channels as usize + ch] = sample;
                    }
                }
            }
            AudioPattern::Silence => {
                // Already filled with zeros
            }
            AudioPattern::Noise => {
                // Simple pseudo-random noise
                let mut seed = self.sample_count;
                for sample in samples.iter_mut() {
                    seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                    *sample = ((seed >> 16) as i16) / 4; // Reduce amplitude
                }
            }
        }

        self.sample_count += count as u64;
        samples
    }

    /// Get the sample rate
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Get the number of channels
    pub fn channels(&self) -> u8 {
        self.channels
    }
}

#[cfg(test)]
mod encoded_frame_tests {
    use super::*;

    #[test]
    fn test_encoded_frames_follow_bitrate() {
        let mut gen = VideoGenerator::new(320, 240, 15, VideoPattern::ColorBars);
        let bitrate = 500_000;
        // 2 seconds at 15 fps: one keyframe, then delta frames
        let sizes: Vec<usize> = (0..30)
            .map(|_| gen.next_encoded_frame(bitrate).data.len())
            .collect();
        let delta = bitrate as usize / 8 / 15;
        assert_eq!(sizes[0], delta * 4, "first frame is a keyframe");
        assert!(sizes[1..].iter().all(|&s| s == delta));
        // ~2 seconds of frames carry roughly 2 seconds of bitrate
        let total_bits = sizes.iter().sum::<usize>() * 8;
        assert!(total_bits < 2 * bitrate as usize * 13 / 10);
    }
}

#[cfg(test)]
mod marker_tests {
    use super::*;

    fn stamped(prefix: &[u8], ssrc: u32, frame: u32) -> Vec<u8> {
        let mut payload = prefix.to_vec();
        let mut body = vec![0xAA; 20];
        assert!(stamp_marker(&mut body, ssrc, frame));
        payload.extend_from_slice(&body);
        payload
    }

    #[test]
    fn audio_marker_is_the_payload_start() {
        let payload = stamped(&[], 0xDEAD_BEEF, 7);
        assert_eq!(read_marker(false, &payload), Some((0xDEAD_BEEF, 7)));
        assert_eq!(read_marker(false, &payload[..7]), None);
        assert!(!stamp_marker(&mut [0u8; 7], 1, 1));
    }

    #[test]
    fn vp8_marker_follows_the_descriptor() {
        // Minimal descriptor, S bit set.
        assert_eq!(read_marker(true, &stamped(&[0x10], 5, 9)), Some((5, 9)));
        // X with a 15-bit picture id, TL0PICIDX and TID/KEYIDX: 6 bytes.
        let ext = [0x90, 0xF0, 0x80 | 0x12, 0x34, 0x01, 0x20];
        assert_eq!(read_marker(true, &stamped(&ext, 6, 10)), Some((6, 10)));
        // X with a 7-bit picture id only: 3 bytes.
        assert_eq!(
            read_marker(true, &stamped(&[0x90, 0x80, 0x12], 8, 11)),
            Some((8, 11))
        );
    }

    #[test]
    fn vp8_packets_that_do_not_start_a_frame_carry_no_marker() {
        // Continuation packet (S clear) and a later partition.
        assert_eq!(read_marker(true, &stamped(&[0x00], 5, 9)), None);
        assert_eq!(read_marker(true, &stamped(&[0x11], 5, 9)), None);
        // Truncated descriptors.
        assert_eq!(read_marker(true, &[]), None);
        assert_eq!(read_marker(true, &[0x90]), None);
        assert_eq!(read_marker(true, &[0x90, 0x80]), None);
        assert_eq!(read_marker(true, &[0x10, 1, 2]), None);
    }
}
