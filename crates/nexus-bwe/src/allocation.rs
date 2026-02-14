/// Track priority for bandwidth allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrackPriority {
    Low = 0,      // Background tracks
    Normal = 1,   // Regular camera
    High = 2,     // Screen share
    Critical = 3, // Active speaker
}

/// Simulcast layer information.
#[derive(Clone, Copy, Debug)]
pub struct SimulcastLayer {
    /// Layer index (0 = lowest, 2 = highest).
    pub index: u8,
    /// Target bitrate for this layer (bps).
    pub bitrate_bps: u64,
    /// Resolution width (0 for audio tracks).
    pub width: u16,
    /// Resolution height (0 for audio tracks).
    pub height: u16,
}

impl SimulcastLayer {
    /// Create new simulcast layer for video.
    ///
    /// # Panics
    ///
    /// Panics if index > 2, bitrate_bps == 0, width == 0, or height == 0.
    pub fn new(index: u8, bitrate_bps: u64, width: u16, height: u16) -> Self {
        assert!(index <= 2, "Layer index must be <= 2, got {}", index);
        assert!(bitrate_bps > 0, "Layer bitrate must be positive");
        assert!(width > 0, "Layer width must be positive");
        assert!(height > 0, "Layer height must be positive");

        Self {
            index,
            bitrate_bps,
            width,
            height,
        }
    }

    /// Create new simulcast layer for audio.
    ///
    /// Audio tracks don't have resolution dimensions, so width and height
    /// are set to 0.
    ///
    /// # Panics
    ///
    /// Panics if index > 2 or bitrate_bps == 0.
    pub fn new_audio(index: u8, bitrate_bps: u64) -> Self {
        assert!(index <= 2, "Layer index must be <= 2, got {}", index);
        assert!(bitrate_bps > 0, "Layer bitrate must be positive");

        Self {
            index,
            bitrate_bps,
            width: 0,
            height: 0,
        }
    }
}

/// Track allocation request.
#[derive(Clone, Debug)]
pub struct TrackAllocation {
    /// Track identifier.
    pub track_id: u64,
    /// Track priority.
    pub priority: TrackPriority,
    /// Maximum bitrate this track can use (bps).
    pub max_bitrate_bps: u64,
    /// Available simulcast layers (pre-allocated, max 3).
    pub layers: [Option<SimulcastLayer>; 3],
    /// Number of valid layers.
    pub layer_count: usize,
    /// Allocated bitrate (output, set by allocator).
    pub allocated_bitrate_bps: u64,
    /// Selected layer index (output).
    pub selected_layer: u8,
}

impl TrackAllocation {
    /// Maximum tracks per allocation.
    pub const MAX_TRACKS: usize = 100;
    /// Maximum layers per track.
    pub const MAX_LAYERS: usize = 3;

    /// Create new track allocation request.
    pub fn new(track_id: u64, priority: TrackPriority, max_bitrate_bps: u64) -> Self {
        assert!(max_bitrate_bps > 0, "Max bitrate must be positive");

        Self {
            track_id,
            priority,
            max_bitrate_bps,
            layers: [None, None, None],
            layer_count: 0,
            allocated_bitrate_bps: 0,
            selected_layer: 0,
        }
    }

    /// Add simulcast layer to track.
    pub fn add_layer(&mut self, layer: SimulcastLayer) {
        assert!(
            self.layer_count < Self::MAX_LAYERS,
            "Cannot add more than {} layers",
            Self::MAX_LAYERS
        );

        // Verify layers are in increasing bitrate order
        if self.layer_count > 0 {
            let prev_layer = self.layers[self.layer_count - 1].unwrap();
            assert!(
                layer.bitrate_bps > prev_layer.bitrate_bps,
                "Layer bitrate {} must be > previous layer bitrate {}",
                layer.bitrate_bps,
                prev_layer.bitrate_bps
            );
        }

        self.layers[self.layer_count] = Some(layer);
        self.layer_count += 1;
    }

    /// Get layer by index.
    pub fn get_layer(&self, index: usize) -> Option<&SimulcastLayer> {
        if index < self.layer_count {
            self.layers[index].as_ref()
        } else {
            None
        }
    }

    /// Get minimum layer bitrate (lowest layer).
    pub fn min_layer_bitrate(&self) -> u64 {
        if self.layer_count > 0 {
            self.layers[0].map(|l| l.bitrate_bps).unwrap_or(0)
        } else {
            0
        }
    }

    /// Select best layer for allocated bitrate.
    pub fn select_layer(&mut self) {
        if self.layer_count == 0 {
            self.selected_layer = 0;
            return;
        }

        // Find highest layer that fits within allocated bitrate
        let mut selected = 0;
        for i in 0..self.layer_count {
            if let Some(layer) = &self.layers[i] {
                if layer.bitrate_bps <= self.allocated_bitrate_bps {
                    selected = layer.index;
                } else {
                    break;
                }
            }
        }

        self.selected_layer = selected;
    }

    /// Verify allocation invariants.
    pub fn verify(&self) {
        assert!(
            self.allocated_bitrate_bps <= self.max_bitrate_bps,
            "Allocated {} exceeds max {}",
            self.allocated_bitrate_bps,
            self.max_bitrate_bps
        );

        // Verify layer ordering
        for i in 1..self.layer_count {
            let prev = self.layers[i - 1].unwrap();
            let curr = self.layers[i].unwrap();
            assert!(
                curr.bitrate_bps > prev.bitrate_bps,
                "Layer {} bitrate {} must be > layer {} bitrate {}",
                i,
                curr.bitrate_bps,
                i - 1,
                prev.bitrate_bps
            );
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_track_priority_ordering() {
        assert!(TrackPriority::Critical > TrackPriority::High);
        assert!(TrackPriority::High > TrackPriority::Normal);
        assert!(TrackPriority::Normal > TrackPriority::Low);
    }

    #[test]
    fn test_simulcast_layer_creation() {
        let layer = SimulcastLayer::new(0, 100_000, 320, 240);
        assert_eq!(layer.index, 0);
        assert_eq!(layer.bitrate_bps, 100_000);
        assert_eq!(layer.width, 320);
        assert_eq!(layer.height, 240);
    }

    #[test]
    fn test_simulcast_layer_audio() {
        let layer = SimulcastLayer::new_audio(0, 64_000);
        assert_eq!(layer.index, 0);
        assert_eq!(layer.bitrate_bps, 64_000);
        assert_eq!(layer.width, 0);
        assert_eq!(layer.height, 0);
    }

    #[test]
    #[should_panic(expected = "Layer index must be <= 2")]
    fn test_simulcast_layer_invalid_index() {
        SimulcastLayer::new(3, 100_000, 320, 240);
    }

    #[test]
    #[should_panic(expected = "Layer index must be <= 2")]
    fn test_simulcast_layer_audio_invalid_index() {
        SimulcastLayer::new_audio(3, 64_000);
    }

    #[test]
    fn test_track_allocation_creation() {
        let allocation = TrackAllocation::new(1, TrackPriority::Normal, 1_000_000);
        assert_eq!(allocation.track_id, 1);
        assert_eq!(allocation.priority, TrackPriority::Normal);
        assert_eq!(allocation.max_bitrate_bps, 1_000_000);
        assert_eq!(allocation.layer_count, 0);
        assert_eq!(allocation.allocated_bitrate_bps, 0);
    }

    #[test]
    fn test_track_allocation_add_layers() {
        let mut allocation = TrackAllocation::new(1, TrackPriority::Normal, 2_000_000);
        
        allocation.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
        allocation.add_layer(SimulcastLayer::new(1, 500_000, 640, 480));
        allocation.add_layer(SimulcastLayer::new(2, 1_500_000, 1280, 720));
        
        assert_eq!(allocation.layer_count, 3);
        assert_eq!(allocation.get_layer(0).unwrap().bitrate_bps, 100_000);
        assert_eq!(allocation.get_layer(1).unwrap().bitrate_bps, 500_000);
        assert_eq!(allocation.get_layer(2).unwrap().bitrate_bps, 1_500_000);
    }

    #[test]
    #[should_panic(expected = "Layer bitrate")]
    fn test_track_allocation_layers_not_increasing() {
        let mut allocation = TrackAllocation::new(1, TrackPriority::Normal, 2_000_000);
        
        allocation.add_layer(SimulcastLayer::new(0, 500_000, 640, 480));
        allocation.add_layer(SimulcastLayer::new(1, 100_000, 320, 240));
    }

    #[test]
    fn test_track_allocation_select_layer() {
        let mut allocation = TrackAllocation::new(1, TrackPriority::Normal, 2_000_000);
        
        allocation.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
        allocation.add_layer(SimulcastLayer::new(1, 500_000, 640, 480));
        allocation.add_layer(SimulcastLayer::new(2, 1_500_000, 1280, 720));
        
        // Select with enough for middle layer
        allocation.allocated_bitrate_bps = 600_000;
        allocation.select_layer();
        assert_eq!(allocation.selected_layer, 1);
        
        // Select with enough for highest layer
        allocation.allocated_bitrate_bps = 2_000_000;
        allocation.select_layer();
        assert_eq!(allocation.selected_layer, 2);
        
        // Select with only enough for lowest layer
        allocation.allocated_bitrate_bps = 150_000;
        allocation.select_layer();
        assert_eq!(allocation.selected_layer, 0);
    }

    #[test]
    fn test_track_allocation_verify() {
        let mut allocation = TrackAllocation::new(1, TrackPriority::Normal, 1_000_000);
        
        allocation.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
        allocation.add_layer(SimulcastLayer::new(1, 500_000, 640, 480));
        
        allocation.allocated_bitrate_bps = 500_000;
        allocation.verify();
    }

    #[test]
    #[should_panic(expected = "Allocated")]
    fn test_track_allocation_verify_exceeds_max() {
        let mut allocation = TrackAllocation::new(1, TrackPriority::Normal, 1_000_000);
        allocation.allocated_bitrate_bps = 2_000_000;
        allocation.verify();
    }

    #[test]
    fn test_track_allocation_min_layer_bitrate() {
        let mut allocation = TrackAllocation::new(1, TrackPriority::Normal, 2_000_000);
        
        // No layers
        assert_eq!(allocation.min_layer_bitrate(), 0);
        
        // Add layers
        allocation.add_layer(SimulcastLayer::new(0, 100_000, 320, 240));
        allocation.add_layer(SimulcastLayer::new(1, 500_000, 640, 480));
        allocation.add_layer(SimulcastLayer::new(2, 1_500_000, 1280, 720));
        
        // Should return lowest layer bitrate
        assert_eq!(allocation.min_layer_bitrate(), 100_000);
    }
}
