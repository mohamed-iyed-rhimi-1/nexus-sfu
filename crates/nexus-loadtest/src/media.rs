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
                let phase_increment = 2.0 * std::f64::consts::PI * freq as f64 / self.sample_rate as f64;
                
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
