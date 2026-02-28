//! Feature extraction primitives.
//!
//! All features are deterministic, numeric, and inspectable.
//! No stochastic models. No hidden state.

/// Compute Shannon entropy (bits) of a byte sequence.
///
/// Returns 0.0 for empty input. Maximum is 8.0 bits for uniformly
/// distributed bytes. Typical values:
/// - English text: ~4.0-4.5 bits
/// - Base64 encoded: ~5.7-6.0 bits
/// - Hex encoded: ~3.5-4.0 bits
/// - Random bytes: ~7.9-8.0 bits
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Beacon features extracted from inter-arrival times.
#[derive(Debug, Clone)]
pub struct BeaconFeatures {
    /// Coefficient of variation of IATs (stddev / mean).
    /// Lower = more regular = more suspicious.
    pub cv: f64,
    /// Mean inter-arrival time in seconds.
    pub mean_iat: f64,
    /// Standard deviation of IATs.
    pub stddev_iat: f64,
    /// Median IAT in seconds.
    pub median_iat: f64,
    /// Fraction of IATs within 10% of the modal interval.
    pub regularity_ratio: f64,
    /// Number of distinct modal peaks in IAT histogram.
    pub mode_count: usize,
    /// Number of IAT samples.
    pub sample_count: usize,
}

/// Compute beacon features from a list of timestamps.
///
/// Timestamps must be in seconds (epoch or relative). The list is
/// sorted in-place. Returns None if fewer than 3 timestamps (need
/// at least 2 IATs for meaningful statistics).
pub fn compute_beacon_features(timestamps: &mut [f64]) -> Option<BeaconFeatures> {
    if timestamps.len() < 3 {
        return None;
    }

    timestamps.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let mut iats: Vec<f64> = Vec::with_capacity(timestamps.len() - 1);
    for i in 1..timestamps.len() {
        let dt = timestamps[i] - timestamps[i - 1];
        if dt > 0.0 {
            iats.push(dt);
        }
    }

    if iats.len() < 2 {
        return None;
    }

    let n = iats.len() as f64;
    let mean = iats.iter().sum::<f64>() / n;

    if mean < f64::EPSILON {
        return None;
    }

    let variance = iats.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let stddev = variance.sqrt();
    let cv = stddev / mean;

    let mut sorted_iats = iats.clone();
    sorted_iats.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = if sorted_iats.len() % 2 == 0 {
        (sorted_iats[sorted_iats.len() / 2 - 1] + sorted_iats[sorted_iats.len() / 2]) / 2.0
    } else {
        sorted_iats[sorted_iats.len() / 2]
    };

    // Regularity: fraction of IATs within 10% of median
    let tolerance = median * 0.1;
    let regular_count = iats
        .iter()
        .filter(|&&x| (x - median).abs() <= tolerance)
        .count();
    let regularity_ratio = regular_count as f64 / n;

    // Mode detection via histogram binning
    let bin_width = mean * 0.05;
    let mode_count = if bin_width > f64::EPSILON {
        let mut bins: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
        for &iat in &iats {
            let bin = (iat / bin_width) as u64;
            *bins.entry(bin).or_insert(0) += 1;
        }
        let max_bin_count = bins.values().max().copied().unwrap_or(0);
        let threshold = (max_bin_count as f64 * 0.5) as usize;
        bins.values().filter(|&&c| c >= threshold).count()
    } else {
        0
    };

    Some(BeaconFeatures {
        cv,
        mean_iat: mean,
        stddev_iat: stddev,
        median_iat: median,
        regularity_ratio,
        mode_count,
        sample_count: iats.len(),
    })
}

/// Compute the alphanumeric ratio of a string.
/// Higher ratios (>0.95) are typical of encoded C2 payloads.
pub fn alphanumeric_ratio(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let alnum = s.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    alnum as f64 / s.len() as f64
}

/// Safely truncate a string to at most `max_bytes` without splitting
/// a multi-byte character. Returns (truncated, was_truncated).
pub fn safe_truncate(s: &str, max_bytes: usize) -> (&str, bool) {
    if s.len() <= max_bytes {
        return (s, false);
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (&s[..end], true)
}

/// Extract the base (parent) domain from an FQDN.
///
/// If the FQDN ends with a known C2 suffix, returns the suffix.
/// Otherwise uses a heuristic: keep last 2 labels (or 3 if the
/// second-to-last is short, indicating a ccTLD like .co.uk).
pub fn extract_base_domain(fqdn: &str, c2_suffixes: &[String]) -> String {
    let lower = fqdn.to_lowercase();
    for suffix in c2_suffixes {
        if lower == *suffix || lower.ends_with(&format!(".{}", suffix)) {
            return suffix.clone();
        }
    }
    let labels: Vec<&str> = lower.split('.').collect();
    if labels.len() <= 2 {
        return lower;
    }
    let keep = if labels.len() >= 3 && labels[labels.len() - 2].len() <= 3 {
        3
    } else {
        2
    };
    labels[labels.len().saturating_sub(keep)..].join(".")
}

/// Check if a domain matches any known C2 suffix.
pub fn is_c2_domain(domain: &str, c2_suffixes: &[String]) -> bool {
    let lower = domain.to_lowercase();
    for suffix in c2_suffixes {
        if lower == *suffix || lower.ends_with(&format!(".{}", suffix)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    #[test]
    fn test_entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let ent = shannon_entropy(&data);
        assert!((ent - 8.0).abs() < 0.01, "uniform bytes should be ~8.0 bits, got {}", ent);
    }

    #[test]
    fn test_entropy_single_byte() {
        let ent = shannon_entropy(b"aaaaaaa");
        assert_eq!(ent, 0.0);
    }

    #[test]
    fn test_beacon_features_regular() {
        let mut ts: Vec<f64> = (0..100).map(|i| i as f64 * 10.0).collect();
        let bf = compute_beacon_features(&mut ts).unwrap();
        assert!(bf.cv < 0.01, "perfectly regular should have CV~0, got {}", bf.cv);
        assert!((bf.mean_iat - 10.0).abs() < 0.1);
    }

    #[test]
    fn test_safe_truncate_ascii() {
        let (s, t) = safe_truncate("hello world", 5);
        assert_eq!(s, "hello");
        assert!(t);
    }

    #[test]
    fn test_safe_truncate_utf8() {
        let s = "hello🌍world";
        let (trunc, _) = safe_truncate(s, 6);
        assert_eq!(trunc, "hello");
    }

    #[test]
    fn test_extract_base_domain_c2() {
        let suffixes = vec!["evil.com".to_string()];
        assert_eq!(extract_base_domain("sub.evil.com", &suffixes), "evil.com");
        assert_eq!(extract_base_domain("deep.sub.evil.com", &suffixes), "evil.com");
        assert_eq!(extract_base_domain("evil.com", &suffixes), "evil.com");
    }

    #[test]
    fn test_extract_base_domain_unknown() {
        let suffixes: Vec<String> = vec![];
        assert_eq!(extract_base_domain("www.google.com", &suffixes), "google.com");
        assert_eq!(extract_base_domain("sub.example.co.uk", &suffixes), "example.co.uk");
    }
}
