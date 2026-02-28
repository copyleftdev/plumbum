//! Composite scoring engine.
//!
//! Computes a single [0, 100] score from normalized feature dimensions
//! and a weight vector. The score is fully decomposable.

use crate::normalize::DomainFeatures;
use crate::weights::Weights;
use plumbum_core::dns::Severity;

/// A scored domain with full decomposition.
#[derive(Debug, Clone)]
pub struct ScoredDomain {
    pub domain: String,
    pub is_c2: bool,
    pub score: f64,
    pub severity: Severity,
    pub contributions: [(&'static str, f64); 6],
    pub features: DomainFeatures,
}

/// Compute composite score in [0, 100].
pub fn composite_score(features: &DomainFeatures, weights: &Weights) -> f64 {
    let raw = features.entropy_norm * weights.entropy
        + features.periodicity_norm * weights.periodicity
        + features.volume_norm * weights.volume
        + features.length_norm * weights.length
        + features.client_rarity_norm * weights.client_rarity
        + features.subdomain_diversity_norm * weights.subdomain_diversity;

    let weight_sum = weights.total();
    if weight_sum < f64::EPSILON {
        return 0.0;
    }

    (raw / weight_sum * 100.0).clamp(0.0, 100.0)
}

/// Score a domain and produce a full decomposition.
pub fn score_domain(features: &DomainFeatures, weights: &Weights) -> ScoredDomain {
    let score = composite_score(features, weights);
    let total = weights.total();

    let contributions = [
        (
            "entropy",
            if total > 0.0 {
                features.entropy_norm * weights.entropy / total * 100.0
            } else {
                0.0
            },
        ),
        (
            "periodicity",
            if total > 0.0 {
                features.periodicity_norm * weights.periodicity / total * 100.0
            } else {
                0.0
            },
        ),
        (
            "volume",
            if total > 0.0 {
                features.volume_norm * weights.volume / total * 100.0
            } else {
                0.0
            },
        ),
        (
            "length",
            if total > 0.0 {
                features.length_norm * weights.length / total * 100.0
            } else {
                0.0
            },
        ),
        (
            "client_rarity",
            if total > 0.0 {
                features.client_rarity_norm * weights.client_rarity / total * 100.0
            } else {
                0.0
            },
        ),
        (
            "subdomain_div",
            if total > 0.0 {
                features.subdomain_diversity_norm * weights.subdomain_diversity / total * 100.0
            } else {
                0.0
            },
        ),
    ];

    ScoredDomain {
        domain: features.domain.clone(),
        is_c2: features.is_c2,
        score,
        severity: Severity::from_score(score),
        contributions,
        features: features.clone(),
    }
}

/// Score and rank a batch of domains. Returns sorted descending by score.
pub fn score_and_rank(features: &[DomainFeatures], weights: &Weights) -> Vec<ScoredDomain> {
    let mut scored: Vec<ScoredDomain> = features.iter().map(|f| score_domain(f, weights)).collect();
    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    scored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_composite_score_basic() {
        let features = DomainFeatures {
            domain: "test.com".into(),
            is_c2: false,
            entropy_norm: 1.0,
            periodicity_norm: 1.0,
            volume_norm: 1.0,
            length_norm: 1.0,
            client_rarity_norm: 1.0,
            subdomain_diversity_norm: 1.0,
        };
        let weights = Weights::default();
        let score = composite_score(&features, &weights);
        assert!(
            (score - 100.0).abs() < 0.01,
            "all-ones should score 100, got {}",
            score
        );
    }

    #[test]
    fn test_composite_score_zero() {
        let features = DomainFeatures {
            domain: "zero.com".into(),
            is_c2: false,
            entropy_norm: 0.0,
            periodicity_norm: 0.0,
            volume_norm: 0.0,
            length_norm: 0.0,
            client_rarity_norm: 0.0,
            subdomain_diversity_norm: 0.0,
        };
        let score = composite_score(&features, &Weights::default());
        assert!(score.abs() < 0.01);
    }

    #[test]
    fn test_score_and_rank() {
        let feats = vec![
            DomainFeatures {
                domain: "low.com".into(),
                is_c2: false,
                entropy_norm: 0.1,
                periodicity_norm: 0.1,
                volume_norm: 0.1,
                length_norm: 0.1,
                client_rarity_norm: 0.1,
                subdomain_diversity_norm: 0.0,
            },
            DomainFeatures {
                domain: "high.com".into(),
                is_c2: true,
                entropy_norm: 0.9,
                periodicity_norm: 0.9,
                volume_norm: 0.9,
                length_norm: 0.9,
                client_rarity_norm: 0.9,
                subdomain_diversity_norm: 0.9,
            },
        ];
        let ranked = score_and_rank(&feats, &Weights::default());
        assert_eq!(ranked[0].domain, "high.com");
        assert!(ranked[0].score > ranked[1].score);
    }
}
