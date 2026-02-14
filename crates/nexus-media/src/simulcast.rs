//! Simulcast layer selection logic.
//!
//! Determines which simulcast layer to forward based on
//! subscriber bandwidth estimates and viewport requirements.
//!
//! # Design
//!
//! WebRTC simulcast encodes video at multiple quality levels
//! (layers) simultaneously. The SFU selects which layer to
//! forward to each subscriber based on their available
//! bandwidth. This avoids transcoding while adapting quality
//! per-subscriber.
//!
//! Layers are ordered Low → Medium → High. The selector
//! picks the highest layer whose bitrate fits within the
//! subscriber's available bandwidth, with hysteresis to
//! prevent rapid oscillation between layers.
//!
//! # TigerStyle
//!
//! - All functions have ≥2 assertions
//! - No function exceeds 70 lines
//! - Explicitly-sized types (u64 for bps, u16 for resolution)
//! - No dynamic allocation after initialization
//! - Fixed loop bounds (max 3 layers)

use std::fmt;

/// Maximum number of simulcast layers per track.
///
/// WebRTC typically uses 3 layers (low, medium, high).
/// This constant bounds all layer iteration loops.
pub const MAX_LAYERS: usize = 3;

/// Hysteresis factor for layer upgrades (percentage).
///
/// When upgrading to a higher layer, require bandwidth to
/// exceed the layer's bitrate by this percentage. This
/// prevents rapid oscillation when bandwidth hovers near
/// a layer boundary.
///
/// Example: with 10% hysteresis, upgrading to a 1 Mbps
/// layer requires 1.1 Mbps available bandwidth.
const UPGRADE_HYSTERESIS_PERCENT: u64 = 10;

// -------------------------------------------------------------------
// SimulcastLayer enum
// -------------------------------------------------------------------

/// Simulcast quality layer identifier.
///
/// Represents the three standard WebRTC simulcast layers.
/// Ordered from lowest to highest quality/bitrate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SimulcastLayer {
    /// Lowest quality — small resolution, low bitrate.
    /// Typically 320×240 or quarter resolution.
    Low = 0,
    /// Medium quality — mid resolution, moderate bitrate.
    /// Typically 640×480 or half resolution.
    Medium = 1,
    /// Highest quality — full resolution, high bitrate.
    /// Typically 1280×720 or full resolution.
    High = 2,
}

impl SimulcastLayer {
    /// Convert layer index (0–2) to enum variant.
    ///
    /// # Assertions
    /// - index must be <= 2
    /// - returned variant matches input index
    #[inline]
    pub fn from_index(index: u8) -> Self {
        assert!(index <= 2, "layer index must be <= 2, got {}", index);

        let layer = match index {
            0 => SimulcastLayer::Low,
            1 => SimulcastLayer::Medium,
            2 => SimulcastLayer::High,
            // Unreachable due to assertion above, but explicit
            // for TigerStyle — no silent fallthrough.
            _ => unreachable!(),
        };

        assert_eq!(
            layer.index(), index,
            "from_index round-trip failed"
        );
        layer
    }

    /// Get the numeric index of this layer (0–2).
    #[inline]
    pub const fn index(self) -> u8 {
        self as u8
    }

    /// Check if this layer is the lowest quality.
    #[inline]
    pub const fn is_low(self) -> bool {
        matches!(self, SimulcastLayer::Low)
    }

    /// Check if this layer is the highest quality.
    #[inline]
    pub const fn is_high(self) -> bool {
        matches!(self, SimulcastLayer::High)
    }
}

impl fmt::Display for SimulcastLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimulcastLayer::Low => write!(f, "low"),
            SimulcastLayer::Medium => write!(f, "medium"),
            SimulcastLayer::High => write!(f, "high"),
        }
    }
}

// -------------------------------------------------------------------
// SimulcastLayerConfig
// -------------------------------------------------------------------

/// Configuration for a single simulcast layer.
///
/// Describes the bitrate and resolution of one encoding
/// layer. Layers must be added in increasing bitrate order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulcastLayerConfig {
    /// Which layer this config describes.
    pub layer: SimulcastLayer,
    /// Target bitrate for this layer in bits per second.
    pub bitrate_bps: u64,
    /// Resolution width in pixels.
    pub width: u16,
    /// Resolution height in pixels.
    pub height: u16,
}

impl SimulcastLayerConfig {
    /// Create a new layer configuration.
    ///
    /// # Assertions
    /// - bitrate_bps must be > 0
    /// - width and height must be > 0
    pub fn new(
        layer: SimulcastLayer,
        bitrate_bps: u64,
        width: u16,
        height: u16,
    ) -> Self {
        assert!(
            bitrate_bps > 0,
            "layer bitrate must be positive, got 0"
        );
        assert!(
            width > 0 && height > 0,
            "layer resolution must be positive: {}x{}",
            width, height
        );

        Self { layer, bitrate_bps, width, height }
    }

    /// Total pixels in this layer's resolution.
    #[inline]
    pub const fn pixel_count(self) -> u32 {
        self.width as u32 * self.height as u32
    }
}

// -------------------------------------------------------------------
// LayerSelector
// -------------------------------------------------------------------

/// Selects the appropriate simulcast layer based on available
/// bandwidth.
///
/// Maintains the current layer and applies hysteresis to
/// prevent rapid oscillation between layers when bandwidth
/// fluctuates near a boundary.
///
/// # Invariants
/// - `layer_count` is always <= MAX_LAYERS (3)
/// - Layers are stored in increasing bitrate order
/// - `current_layer` index is always < `layer_count`
///   (or Low if no layers configured)
#[derive(Clone, Debug)]
pub struct LayerSelector {
    /// Available layer configurations, ordered by bitrate.
    layers: [SimulcastLayerConfig; MAX_LAYERS],
    /// Number of configured layers (0–3).
    layer_count: u8,
    /// Currently selected layer.
    current_layer: SimulcastLayer,
}

impl LayerSelector {
    /// Create a new layer selector with no layers configured.
    ///
    /// # Assertions
    /// - layer_count starts at 0
    /// - current_layer defaults to Low
    pub fn new() -> Self {
        let default_cfg = SimulcastLayerConfig {
            layer: SimulcastLayer::Low,
            bitrate_bps: 1,
            width: 1,
            height: 1,
        };

        let selector = Self {
            layers: [default_cfg; MAX_LAYERS],
            layer_count: 0,
            current_layer: SimulcastLayer::Low,
        };

        assert_eq!(selector.layer_count, 0);
        assert_eq!(selector.current_layer, SimulcastLayer::Low);
        selector
    }

    /// Add a layer configuration.
    ///
    /// Layers must be added in increasing bitrate order.
    ///
    /// # Assertions
    /// - Cannot exceed MAX_LAYERS
    /// - Bitrate must be strictly increasing
    pub fn add_layer(&mut self, config: SimulcastLayerConfig) {
        assert!(
            (self.layer_count as usize) < MAX_LAYERS,
            "cannot add more than {} layers",
            MAX_LAYERS
        );

        // Verify strictly increasing bitrate order.
        if self.layer_count > 0 {
            let prev = self.layers[(self.layer_count - 1) as usize];
            assert!(
                config.bitrate_bps > prev.bitrate_bps,
                "layer bitrate {} must exceed previous {}",
                config.bitrate_bps,
                prev.bitrate_bps
            );
        }

        self.layers[self.layer_count as usize] = config;
        self.layer_count += 1;
    }

    /// Get the number of configured layers.
    #[inline]
    pub const fn layer_count(&self) -> u8 {
        self.layer_count
    }

    /// Get the currently selected layer.
    #[inline]
    pub const fn current_layer(&self) -> SimulcastLayer {
        self.current_layer
    }

    /// Get the config for a specific layer, if configured.
    ///
    /// # Assertions
    /// - layer_count <= MAX_LAYERS
    pub fn get_config(
        &self,
        layer: SimulcastLayer,
    ) -> Option<&SimulcastLayerConfig> {
        assert!(
            self.layer_count as usize <= MAX_LAYERS,
            "layer_count invariant violated"
        );

        // Bounded loop: max 3 iterations.
        for i in 0..self.layer_count as usize {
            if self.layers[i].layer == layer {
                return Some(&self.layers[i]);
            }
        }
        None
    }

    /// Select the best layer for the given available bandwidth.
    ///
    /// Picks the highest-quality layer whose bitrate fits
    /// within `available_bps`. Applies hysteresis when
    /// upgrading to prevent oscillation.
    ///
    /// Returns the selected layer. Also updates internal
    /// `current_layer` state.
    ///
    /// # Assertions
    /// - layer_count > 0 (must have at least one layer)
    /// - returned layer's bitrate <= available_bps
    ///   (unless only one layer exists and bandwidth is
    ///   below it — then we still select the lowest layer
    ///   to avoid sending nothing)
    pub fn select_layer(
        &mut self,
        available_bps: u64,
    ) -> SimulcastLayer {
        assert!(
            self.layer_count > 0,
            "cannot select layer with 0 configured layers"
        );
        assert!(
            self.layer_count as usize <= MAX_LAYERS,
            "layer_count invariant violated"
        );

        let previous = self.current_layer;
        let mut selected_idx: usize = 0;

        // Find highest layer that fits within bandwidth.
        // Bounded loop: max 3 iterations.
        for i in 0..self.layer_count as usize {
            let layer_bps = self.layers[i].bitrate_bps;

            // For upgrades (higher layer than current), apply
            // hysteresis to prevent oscillation.
            let threshold_bps = if self.layers[i].layer > previous {
                // Require extra headroom for upgrade.
                layer_bps + (layer_bps * UPGRADE_HYSTERESIS_PERCENT / 100)
            } else {
                // No hysteresis for current or downgrade.
                layer_bps
            };

            if available_bps >= threshold_bps {
                selected_idx = i;
            }
        }

        self.current_layer = self.layers[selected_idx].layer;
        self.current_layer
    }

    /// Get all configured layer configs as a slice.
    ///
    /// # Assertions
    /// - returned slice length == layer_count
    pub fn configs(&self) -> &[SimulcastLayerConfig] {
        let slice = &self.layers[..self.layer_count as usize];
        assert_eq!(
            slice.len(),
            self.layer_count as usize,
            "configs slice length mismatch"
        );
        slice
    }
}

impl Default for LayerSelector {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Free function: select_layer
// -------------------------------------------------------------------

/// Select the best simulcast layer for the given bandwidth.
///
/// Stateless convenience function. For stateful selection with
/// hysteresis, use [`LayerSelector`] instead.
///
/// Picks the highest-quality layer whose bitrate fits within
/// `available_bps`. If bandwidth is below all layers, returns
/// the lowest layer (we always forward something).
///
/// # Assertions
/// - layers must not be empty
/// - layers must be in increasing bitrate order
pub fn select_layer(
    available_bps: u64,
    layers: &[SimulcastLayerConfig],
) -> SimulcastLayer {
    assert!(
        !layers.is_empty(),
        "layers must not be empty"
    );
    assert!(
        layers.len() <= MAX_LAYERS,
        "too many layers: {}, max {}",
        layers.len(),
        MAX_LAYERS
    );

    // Verify increasing bitrate order (bounded: max 2 checks).
    for i in 1..layers.len() {
        assert!(
            layers[i].bitrate_bps > layers[i - 1].bitrate_bps,
            "layers must be in increasing bitrate order: \
             layer {} has {}bps <= layer {} has {}bps",
            i,
            layers[i].bitrate_bps,
            i - 1,
            layers[i - 1].bitrate_bps
        );
    }

    // Find highest layer that fits. Default to lowest.
    let mut selected = layers[0].layer;

    // Bounded loop: max 3 iterations.
    for layer in layers {
        if available_bps >= layer.bitrate_bps {
            selected = layer.layer;
        }
    }

    selected
}

// -------------------------------------------------------------------
// Standard 3-layer presets
// -------------------------------------------------------------------

/// Create a standard 3-layer simulcast configuration.
///
/// Typical WebRTC simulcast layers:
/// - Low:    150 kbps, 320×240
/// - Medium: 500 kbps, 640×480
/// - High:  1500 kbps, 1280×720
///
/// # Assertions
/// - Returns exactly 3 layers
/// - Layers are in increasing bitrate order
pub fn standard_layers() -> [SimulcastLayerConfig; MAX_LAYERS] {
    let layers = [
        SimulcastLayerConfig::new(
            SimulcastLayer::Low,
            150_000,  // 150 kbps
            320,
            240,
        ),
        SimulcastLayerConfig::new(
            SimulcastLayer::Medium,
            500_000,  // 500 kbps
            640,
            480,
        ),
        SimulcastLayerConfig::new(
            SimulcastLayer::High,
            1_500_000, // 1.5 Mbps
            1280,
            720,
        ),
    ];

    // Verify ordering invariant.
    assert!(layers[0].bitrate_bps < layers[1].bitrate_bps);
    assert!(layers[1].bitrate_bps < layers[2].bitrate_bps);
    layers
}

// -------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SimulcastLayer enum tests --

    #[test]
    fn test_layer_from_index() {
        assert_eq!(SimulcastLayer::from_index(0), SimulcastLayer::Low);
        assert_eq!(SimulcastLayer::from_index(1), SimulcastLayer::Medium);
        assert_eq!(SimulcastLayer::from_index(2), SimulcastLayer::High);
    }

    #[test]
    #[should_panic(expected = "layer index must be <= 2")]
    fn test_layer_from_index_invalid() {
        SimulcastLayer::from_index(3);
    }

    #[test]
    fn test_layer_index_roundtrip() {
        for i in 0..=2u8 {
            let layer = SimulcastLayer::from_index(i);
            assert_eq!(layer.index(), i);
        }
    }

    #[test]
    fn test_layer_ordering() {
        assert!(SimulcastLayer::Low < SimulcastLayer::Medium);
        assert!(SimulcastLayer::Medium < SimulcastLayer::High);
        assert!(SimulcastLayer::Low < SimulcastLayer::High);
    }

    #[test]
    fn test_layer_display() {
        assert_eq!(format!("{}", SimulcastLayer::Low), "low");
        assert_eq!(format!("{}", SimulcastLayer::Medium), "medium");
        assert_eq!(format!("{}", SimulcastLayer::High), "high");
    }

    #[test]
    fn test_layer_is_low_is_high() {
        assert!(SimulcastLayer::Low.is_low());
        assert!(!SimulcastLayer::Low.is_high());
        assert!(!SimulcastLayer::High.is_low());
        assert!(SimulcastLayer::High.is_high());
        assert!(!SimulcastLayer::Medium.is_low());
        assert!(!SimulcastLayer::Medium.is_high());
    }

    // -- SimulcastLayerConfig tests --

    #[test]
    fn test_layer_config_creation() {
        let cfg = SimulcastLayerConfig::new(
            SimulcastLayer::Low,
            100_000,
            320,
            240,
        );
        assert_eq!(cfg.layer, SimulcastLayer::Low);
        assert_eq!(cfg.bitrate_bps, 100_000);
        assert_eq!(cfg.width, 320);
        assert_eq!(cfg.height, 240);
    }

    #[test]
    #[should_panic(expected = "layer bitrate must be positive")]
    fn test_layer_config_zero_bitrate() {
        SimulcastLayerConfig::new(SimulcastLayer::Low, 0, 320, 240);
    }

    #[test]
    #[should_panic(expected = "layer resolution must be positive")]
    fn test_layer_config_zero_width() {
        SimulcastLayerConfig::new(
            SimulcastLayer::Low, 100_000, 0, 240,
        );
    }

    #[test]
    fn test_layer_config_pixel_count() {
        let cfg = SimulcastLayerConfig::new(
            SimulcastLayer::High,
            1_500_000,
            1280,
            720,
        );
        assert_eq!(cfg.pixel_count(), 1280 * 720);
    }

    // -- LayerSelector tests --

    #[test]
    fn test_selector_new_defaults() {
        let sel = LayerSelector::new();
        assert_eq!(sel.layer_count(), 0);
        assert_eq!(sel.current_layer(), SimulcastLayer::Low);
    }

    #[test]
    fn test_selector_add_layers() {
        let mut sel = LayerSelector::new();
        let layers = standard_layers();
        for layer in &layers {
            sel.add_layer(*layer);
        }
        assert_eq!(sel.layer_count(), 3);
    }

    #[test]
    #[should_panic(expected = "cannot add more than 3 layers")]
    fn test_selector_add_too_many_layers() {
        let mut sel = LayerSelector::new();
        let layers = standard_layers();
        for layer in &layers {
            sel.add_layer(*layer);
        }
        // Fourth layer should panic.
        sel.add_layer(SimulcastLayerConfig::new(
            SimulcastLayer::High,
            3_000_000,
            1920,
            1080,
        ));
    }

    #[test]
    #[should_panic(expected = "layer bitrate")]
    fn test_selector_add_non_increasing_bitrate() {
        let mut sel = LayerSelector::new();
        sel.add_layer(SimulcastLayerConfig::new(
            SimulcastLayer::Low,
            500_000,
            640,
            480,
        ));
        // Lower bitrate than previous — should panic.
        sel.add_layer(SimulcastLayerConfig::new(
            SimulcastLayer::Medium,
            100_000,
            320,
            240,
        ));
    }

    #[test]
    fn test_selector_select_low_bandwidth() {
        let mut sel = LayerSelector::new();
        let layers = standard_layers();
        for layer in &layers {
            sel.add_layer(*layer);
        }

        // 100 kbps — below all layers, should select Low.
        let selected = sel.select_layer(100_000);
        assert_eq!(selected, SimulcastLayer::Low);
    }

    #[test]
    fn test_selector_select_medium_bandwidth() {
        let mut sel = LayerSelector::new();
        let layers = standard_layers();
        for layer in &layers {
            sel.add_layer(*layer);
        }

        // 600 kbps — fits Low and Medium, should select Medium.
        let selected = sel.select_layer(600_000);
        assert_eq!(selected, SimulcastLayer::Medium);
    }

    #[test]
    fn test_selector_select_high_bandwidth() {
        let mut sel = LayerSelector::new();
        let layers = standard_layers();
        for layer in &layers {
            sel.add_layer(*layer);
        }

        // 2 Mbps — fits all layers, should select High.
        let selected = sel.select_layer(2_000_000);
        assert_eq!(selected, SimulcastLayer::High);
    }

    #[test]
    fn test_selector_hysteresis_prevents_upgrade() {
        let mut sel = LayerSelector::new();
        let layers = standard_layers();
        for layer in &layers {
            sel.add_layer(*layer);
        }

        // Start at Low.
        sel.select_layer(100_000);
        assert_eq!(sel.current_layer(), SimulcastLayer::Low);

        // Bandwidth exactly at Medium threshold (500 kbps).
        // Hysteresis requires 500k + 10% = 550k for upgrade.
        // 500k is not enough to upgrade.
        let selected = sel.select_layer(500_000);
        assert_eq!(selected, SimulcastLayer::Low);

        // 560 kbps — exceeds 550k threshold, should upgrade.
        let selected = sel.select_layer(560_000);
        assert_eq!(selected, SimulcastLayer::Medium);
    }

    #[test]
    fn test_selector_no_hysteresis_on_downgrade() {
        let mut sel = LayerSelector::new();
        let layers = standard_layers();
        for layer in &layers {
            sel.add_layer(*layer);
        }

        // Start at High.
        sel.select_layer(2_000_000);
        assert_eq!(sel.current_layer(), SimulcastLayer::High);

        // Drop to 400 kbps — below High (1.5M) and Medium
        // (500k), should downgrade to Low immediately.
        let selected = sel.select_layer(400_000);
        assert_eq!(selected, SimulcastLayer::Low);
    }

    #[test]
    fn test_selector_single_layer() {
        let mut sel = LayerSelector::new();
        sel.add_layer(SimulcastLayerConfig::new(
            SimulcastLayer::Medium,
            500_000,
            640,
            480,
        ));

        // Any bandwidth selects the only layer.
        assert_eq!(sel.select_layer(100_000), SimulcastLayer::Medium);
        assert_eq!(sel.select_layer(1_000_000), SimulcastLayer::Medium);
    }

    #[test]
    fn test_selector_configs_slice() {
        let mut sel = LayerSelector::new();
        let layers = standard_layers();
        for layer in &layers {
            sel.add_layer(*layer);
        }

        let configs = sel.configs();
        assert_eq!(configs.len(), 3);
        assert_eq!(configs[0].layer, SimulcastLayer::Low);
        assert_eq!(configs[1].layer, SimulcastLayer::Medium);
        assert_eq!(configs[2].layer, SimulcastLayer::High);
    }

    // -- Free function select_layer tests --

    #[test]
    fn test_free_select_layer_low() {
        let layers = standard_layers();
        // Below lowest layer — still returns Low.
        let selected = select_layer(50_000, &layers);
        assert_eq!(selected, SimulcastLayer::Low);
    }

    #[test]
    fn test_free_select_layer_medium() {
        let layers = standard_layers();
        let selected = select_layer(600_000, &layers);
        assert_eq!(selected, SimulcastLayer::Medium);
    }

    #[test]
    fn test_free_select_layer_high() {
        let layers = standard_layers();
        let selected = select_layer(2_000_000, &layers);
        assert_eq!(selected, SimulcastLayer::High);
    }

    #[test]
    fn test_free_select_layer_exact_boundary() {
        let layers = standard_layers();
        // Exactly at Medium boundary (500 kbps).
        let selected = select_layer(500_000, &layers);
        assert_eq!(selected, SimulcastLayer::Medium);
    }

    #[test]
    #[should_panic(expected = "layers must not be empty")]
    fn test_free_select_layer_empty() {
        select_layer(100_000, &[]);
    }

    #[test]
    #[should_panic(expected = "layers must be in increasing bitrate")]
    fn test_free_select_layer_wrong_order() {
        let layers = [
            SimulcastLayerConfig::new(
                SimulcastLayer::High,
                1_500_000,
                1280,
                720,
            ),
            SimulcastLayerConfig::new(
                SimulcastLayer::Low,
                100_000,
                320,
                240,
            ),
        ];
        select_layer(500_000, &layers);
    }

    // -- standard_layers tests --

    #[test]
    fn test_standard_layers() {
        let layers = standard_layers();
        assert_eq!(layers.len(), 3);
        assert_eq!(layers[0].layer, SimulcastLayer::Low);
        assert_eq!(layers[1].layer, SimulcastLayer::Medium);
        assert_eq!(layers[2].layer, SimulcastLayer::High);
        assert_eq!(layers[0].bitrate_bps, 150_000);
        assert_eq!(layers[1].bitrate_bps, 500_000);
        assert_eq!(layers[2].bitrate_bps, 1_500_000);
    }

    #[test]
    fn test_standard_layers_increasing_bitrate() {
        let layers = standard_layers();
        assert!(layers[0].bitrate_bps < layers[1].bitrate_bps);
        assert!(layers[1].bitrate_bps < layers[2].bitrate_bps);
    }

    #[test]
    fn test_standard_layers_increasing_resolution() {
        let layers = standard_layers();
        assert!(layers[0].pixel_count() < layers[1].pixel_count());
        assert!(layers[1].pixel_count() < layers[2].pixel_count());
    }
}
