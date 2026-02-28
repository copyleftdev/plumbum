//! Score explanation engine.
//!
//! Produces human-readable and machine-parseable breakdowns of
//! how a domain's composite score was computed.

use crate::composite::ScoredDomain;
use crate::weights::Weights;

/// A single feature contribution in an explanation.
#[derive(Debug, Clone)]
pub struct FeatureExplanation {
    pub name: &'static str,
    pub raw_value: f64,
    pub normalized: f64,
    pub weight: f64,
    pub contribution: f64,
    pub pct_of_total: f64,
}

/// Full explanation of a scored domain.
#[derive(Debug, Clone)]
pub struct Explanation {
    pub domain: String,
    pub score: f64,
    pub severity: String,
    pub features: Vec<FeatureExplanation>,
}

/// Generate a full explanation for a scored domain.
pub fn explain(scored: &ScoredDomain, weights: &Weights) -> Explanation {
    let total = weights.total();
    let f = &scored.features;

    let features = vec![
        FeatureExplanation {
            name: "entropy",
            raw_value: f.entropy_norm,
            normalized: f.entropy_norm,
            weight: weights.entropy,
            contribution: f.entropy_norm * weights.entropy,
            pct_of_total: if total > 0.0 { f.entropy_norm * weights.entropy / total * 100.0 } else { 0.0 },
        },
        FeatureExplanation {
            name: "periodicity",
            raw_value: f.periodicity_norm,
            normalized: f.periodicity_norm,
            weight: weights.periodicity,
            contribution: f.periodicity_norm * weights.periodicity,
            pct_of_total: if total > 0.0 { f.periodicity_norm * weights.periodicity / total * 100.0 } else { 0.0 },
        },
        FeatureExplanation {
            name: "volume",
            raw_value: f.volume_norm,
            normalized: f.volume_norm,
            weight: weights.volume,
            contribution: f.volume_norm * weights.volume,
            pct_of_total: if total > 0.0 { f.volume_norm * weights.volume / total * 100.0 } else { 0.0 },
        },
        FeatureExplanation {
            name: "length",
            raw_value: f.length_norm,
            normalized: f.length_norm,
            weight: weights.length,
            contribution: f.length_norm * weights.length,
            pct_of_total: if total > 0.0 { f.length_norm * weights.length / total * 100.0 } else { 0.0 },
        },
        FeatureExplanation {
            name: "client_rarity",
            raw_value: f.client_rarity_norm,
            normalized: f.client_rarity_norm,
            weight: weights.client_rarity,
            contribution: f.client_rarity_norm * weights.client_rarity,
            pct_of_total: if total > 0.0 { f.client_rarity_norm * weights.client_rarity / total * 100.0 } else { 0.0 },
        },
        FeatureExplanation {
            name: "subdomain_diversity",
            raw_value: f.subdomain_diversity_norm,
            normalized: f.subdomain_diversity_norm,
            weight: weights.subdomain_diversity,
            contribution: f.subdomain_diversity_norm * weights.subdomain_diversity,
            pct_of_total: if total > 0.0 { f.subdomain_diversity_norm * weights.subdomain_diversity / total * 100.0 } else { 0.0 },
        },
    ];

    Explanation {
        domain: scored.domain.clone(),
        score: scored.score,
        severity: scored.severity.as_str().to_string(),
        features,
    }
}

/// Format an explanation as structured text (for `plumbum explain`).
pub fn format_explanation(expl: &Explanation) -> String {
    let mut out = String::new();
    out.push_str(&format!("Domain: {}\n", expl.domain));
    out.push_str(&format!("Score:  {:.1} ({})\n\n", expl.score, expl.severity));
    out.push_str("Components:\n");

    for fe in &expl.features {
        out.push_str(&format!(
            "  {:<22} norm={:.3}  w={:.4}  contrib={:.3}  ({:.1}%)\n",
            fe.name, fe.normalized, fe.weight, fe.contribution, fe.pct_of_total
        ));
    }

    out
}
