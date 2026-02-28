//! Feature normalization for composite scoring.
//!
//! All features are normalized to [0.0, 1.0] before weighting.
//! Normalization is deterministic and uses corpus-level statistics.

/// Normalized feature vector for a single domain.
#[derive(Debug, Clone)]
pub struct DomainFeatures {
    pub domain: String,
    pub is_c2: bool,
    pub entropy_norm: f64,
    pub periodicity_norm: f64,
    pub volume_norm: f64,
    pub length_norm: f64,
    pub client_rarity_norm: f64,
    pub subdomain_diversity_norm: f64,
}

/// Raw (pre-normalization) feature values for a domain.
#[derive(Debug, Clone)]
pub struct RawFeatures {
    pub domain: String,
    pub is_c2: bool,
    pub mean_entropy: f64,
    pub cv: f64,
    pub query_count: usize,
    pub mean_txt_length: f64,
    pub client_count: usize,
    pub subdomain_count: usize,
}

/// Corpus-level statistics needed for normalization.
#[derive(Debug, Clone)]
pub struct CorpusStats {
    pub entropy_min: f64,
    pub entropy_max: f64,
    pub cv_min: f64,
    pub cv_max: f64,
    pub volume_max: f64,
    pub length_max: f64,
    pub client_max: f64,
    pub subdomain_max: f64,
}

impl CorpusStats {
    /// Compute corpus stats from a set of raw features.
    pub fn from_raw(features: &[RawFeatures]) -> Self {
        if features.is_empty() {
            return Self {
                entropy_min: 0.0,
                entropy_max: 1.0,
                cv_min: 0.0,
                cv_max: 1.0,
                volume_max: 1.0,
                length_max: 1.0,
                client_max: 1.0,
                subdomain_max: 1.0,
            };
        }

        let mut ent_min = f64::MAX;
        let mut ent_max = f64::MIN;
        let mut cv_min = f64::MAX;
        let mut cv_max = f64::MIN;
        let mut vol_max = 0usize;
        let mut len_max = 0.0f64;
        let mut cli_max = 0usize;
        let mut sub_max = 0usize;

        for f in features {
            if f.mean_entropy < ent_min {
                ent_min = f.mean_entropy;
            }
            if f.mean_entropy > ent_max {
                ent_max = f.mean_entropy;
            }
            if f.cv < cv_min {
                cv_min = f.cv;
            }
            if f.cv > cv_max {
                cv_max = f.cv;
            }
            if f.query_count > vol_max {
                vol_max = f.query_count;
            }
            if f.mean_txt_length > len_max {
                len_max = f.mean_txt_length;
            }
            if f.client_count > cli_max {
                cli_max = f.client_count;
            }
            if f.subdomain_count > sub_max {
                sub_max = f.subdomain_count;
            }
        }

        Self {
            entropy_min: ent_min,
            entropy_max: ent_max,
            cv_min,
            cv_max,
            volume_max: vol_max.max(1) as f64,
            length_max: len_max.max(1.0),
            client_max: cli_max.max(1) as f64,
            subdomain_max: sub_max.max(1) as f64,
        }
    }
}

/// Normalize a single domain's raw features against corpus stats.
pub fn normalize(raw: &RawFeatures, stats: &CorpusStats) -> DomainFeatures {
    let range_norm = |v: f64, min: f64, max: f64| -> f64 {
        if (max - min).abs() < f64::EPSILON {
            return 0.0;
        }
        ((v - min) / (max - min)).clamp(0.0, 1.0)
    };
    let inv_norm = |v: f64, min: f64, max: f64| -> f64 { 1.0 - range_norm(v, min, max) };

    DomainFeatures {
        domain: raw.domain.clone(),
        is_c2: raw.is_c2,
        entropy_norm: range_norm(raw.mean_entropy, stats.entropy_min, stats.entropy_max),
        periodicity_norm: inv_norm(raw.cv, stats.cv_min, stats.cv_max),
        volume_norm: range_norm(raw.query_count as f64, 0.0, stats.volume_max),
        length_norm: range_norm(raw.mean_txt_length, 0.0, stats.length_max),
        client_rarity_norm: inv_norm(raw.client_count as f64, 1.0, stats.client_max),
        subdomain_diversity_norm: range_norm(raw.subdomain_count as f64, 0.0, stats.subdomain_max),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_basic() {
        let raw = RawFeatures {
            domain: "test.com".into(),
            is_c2: false,
            mean_entropy: 5.0,
            cv: 0.5,
            query_count: 100,
            mean_txt_length: 30.0,
            client_count: 10,
            subdomain_count: 5,
        };
        let stats = CorpusStats {
            entropy_min: 3.0,
            entropy_max: 7.0,
            cv_min: 0.0,
            cv_max: 2.0,
            volume_max: 200.0,
            length_max: 60.0,
            client_max: 50.0,
            subdomain_max: 100.0,
        };
        let norm = normalize(&raw, &stats);
        assert!((norm.entropy_norm - 0.5).abs() < 0.01);
        assert!((norm.volume_norm - 0.5).abs() < 0.01);
        assert!((norm.length_norm - 0.5).abs() < 0.01);
    }
}
