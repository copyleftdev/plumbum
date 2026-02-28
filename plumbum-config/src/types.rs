//! Configuration types for Plumbum.

/// Top-level Plumbum configuration.
#[derive(Debug, Clone)]
pub struct PlumbumConfig {
    pub analysis: AnalysisConfig,
    pub thresholds: ThresholdConfig,
    pub input: InputConfig,
}

/// Analysis weight configuration.
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    pub entropy_weight: f64,
    pub periodicity_weight: f64,
    pub volume_weight: f64,
    pub length_weight: f64,
    pub client_rarity_weight: f64,
    pub subdomain_diversity_weight: f64,
    pub weight_preset: Option<String>,
}

/// Severity threshold configuration.
#[derive(Debug, Clone)]
pub struct ThresholdConfig {
    pub critical: f64,
    pub high: f64,
    pub medium: f64,
}

/// Input source configuration.
#[derive(Debug, Clone)]
pub struct InputConfig {
    pub paths: Vec<String>,
    pub c2_domains: Vec<String>,
    pub format: Option<String>,
}
