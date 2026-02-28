//! Real-time scoring of accumulated domain features.
//!
//! Scores domains as their windows expire and emits alerts
//! for domains exceeding the configured severity threshold.

use plumbum_core::dns::Severity;
use plumbum_score::composite::composite_score;
use plumbum_score::normalize::{normalize, CorpusStats, DomainFeatures, RawFeatures};
use plumbum_score::weights::Weights;
use serde::Serialize;

/// A scored alert emitted when a domain exceeds the threshold.
#[derive(Debug, Clone, Serialize)]
pub struct StreamAlert {
    pub domain: String,
    pub score: f64,
    pub severity: String,
    pub query_count: usize,
    pub client_count: usize,
    pub subdomain_count: usize,
    pub mean_entropy: f64,
    pub cv: f64,
    pub mean_txt_length: f64,
    pub window_secs: f64,
    pub is_c2: bool,
}

/// Configuration for the stream scorer.
#[derive(Debug, Clone)]
pub struct ScorerConfig {
    pub weights: Weights,
    pub alert_threshold: f64,
    pub window_secs: f64,
}

impl Default for ScorerConfig {
    fn default() -> Self {
        Self {
            weights: Weights::regularized(),
            alert_threshold: 40.0,
            window_secs: 60.0,
        }
    }
}

/// Score a batch of expired RawFeatures and return alerts above threshold.
pub fn score_batch(features: &[RawFeatures], config: &ScorerConfig) -> Vec<StreamAlert> {
    if features.is_empty() {
        return Vec::new();
    }

    let stats = CorpusStats::from_raw(features);
    let mut alerts = Vec::new();

    for raw in features {
        let norm: DomainFeatures = normalize(raw, &stats);
        let score = composite_score(&norm, &config.weights);
        let severity = Severity::from_score(score);

        if score >= config.alert_threshold {
            alerts.push(StreamAlert {
                domain: raw.domain.clone(),
                score,
                severity: severity.as_str().to_string(),
                query_count: raw.query_count,
                client_count: raw.client_count,
                subdomain_count: raw.subdomain_count,
                mean_entropy: raw.mean_entropy,
                cv: raw.cv,
                mean_txt_length: raw.mean_txt_length,
                window_secs: config.window_secs,
                is_c2: raw.is_c2,
            });
        }
    }

    alerts.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    alerts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_batch_empty() {
        let config = ScorerConfig::default();
        let alerts = score_batch(&[], &config);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_score_batch_below_threshold() {
        let config = ScorerConfig {
            alert_threshold: 99.0,
            ..Default::default()
        };
        let features = vec![RawFeatures {
            domain: "benign.com".into(),
            is_c2: false,
            mean_entropy: 3.0,
            cv: 1.5,
            query_count: 5,
            mean_txt_length: 10.0,
            client_count: 50,
            subdomain_count: 2,
        }];
        let alerts = score_batch(&features, &config);
        assert!(alerts.is_empty());
    }
}
