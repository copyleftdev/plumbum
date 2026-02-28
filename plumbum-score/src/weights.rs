//! Weight presets for composite scoring.
//!
//! Three presets available:
//! - `default()`: balanced weights for synthetic/general use
//! - `optimized()`: SA-tuned (2.5M iterations) for max C2/benign separation
//! - `regularized()`: SA-informed with enforced feature diversity

/// Weight vector for composite scoring.
/// Each field corresponds to a normalized feature dimension.
#[derive(Debug, Clone)]
pub struct Weights {
    pub entropy: f64,
    pub periodicity: f64,
    pub volume: f64,
    pub length: f64,
    pub client_rarity: f64,
    pub subdomain_diversity: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            entropy: 1.0,
            periodicity: 1.2,
            volume: 0.5,
            length: 0.8,
            client_rarity: 0.6,
            subdomain_diversity: 0.0,
        }
    }
}

impl Weights {
    /// SA-optimized weights (2.5M iterations, 5 restarts, seed=42).
    /// Achieves 5/5 TP at CRITICAL, 0/10 FP, gap=27.6 points.
    ///
    /// client_rarity dominates (87.4%) because the training corpus
    /// uses popular public domains as benign baseline. Use `regularized()`
    /// for deployments where client diversity may be low across the board.
    pub fn optimized() -> Self {
        Self {
            entropy: 0.0100,
            periodicity: 0.0100,
            volume: 0.1174,
            length: 0.0100,
            client_rarity: 2.1885,
            subdomain_diversity: 0.1692,
        }
    }

    /// SA-informed but with enforced minimum feature diversity.
    /// Keeps client_rarity dominant while ensuring other features
    /// contribute meaningfully. All 5 real C2 tools score >= HIGH (60).
    pub fn regularized() -> Self {
        Self {
            entropy: 0.15,
            periodicity: 0.10,
            volume: 0.25,
            length: 0.10,
            client_rarity: 1.80,
            subdomain_diversity: 0.30,
        }
    }

    /// Construct from an HCL config or custom values.
    pub fn custom(
        entropy: f64, periodicity: f64, volume: f64,
        length: f64, client_rarity: f64, subdomain_diversity: f64,
    ) -> Self {
        Self { entropy, periodicity, volume, length, client_rarity, subdomain_diversity }
    }

    /// Sum of all weights (for normalization).
    pub fn total(&self) -> f64 {
        self.entropy + self.periodicity + self.volume
            + self.length + self.client_rarity + self.subdomain_diversity
    }

    /// Return weights as a named slice for iteration.
    pub fn as_pairs(&self) -> [(&'static str, f64); 6] {
        [
            ("entropy", self.entropy),
            ("periodicity", self.periodicity),
            ("volume", self.volume),
            ("length", self.length),
            ("client_rarity", self.client_rarity),
            ("subdomain_diversity", self.subdomain_diversity),
        ]
    }
}
