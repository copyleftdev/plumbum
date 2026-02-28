//! Default configuration values.

use crate::types::*;

impl Default for PlumbumConfig {
    fn default() -> Self {
        Self {
            analysis: AnalysisConfig::default(),
            thresholds: ThresholdConfig::default(),
            input: InputConfig::default(),
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            entropy_weight: 0.15,
            periodicity_weight: 0.10,
            volume_weight: 0.25,
            length_weight: 0.10,
            client_rarity_weight: 1.80,
            subdomain_diversity_weight: 0.30,
            weight_preset: Some("regularized".to_string()),
        }
    }
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            critical: 80.0,
            high: 60.0,
            medium: 40.0,
        }
    }
}

impl Default for InputConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            c2_domains: Vec::new(),
            format: None,
        }
    }
}

/// Default HCL config file content.
pub const DEFAULT_CONFIG_HCL: &str = r#"analysis {
  weight_preset           = "regularized"
  entropy_weight          = 0.15
  periodicity_weight      = 0.10
  volume_weight           = 0.25
  length_weight           = 0.10
  client_rarity_weight    = 1.80
  subdomain_diversity_weight = 0.30
}

thresholds {
  critical = 80
  high     = 60
  medium   = 40
}
"#;
