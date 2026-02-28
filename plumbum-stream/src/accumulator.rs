//! Sliding window accumulator for live DNS records.
//!
//! Groups DnsRecord values by base domain, tracks per-domain
//! statistics over a configurable time window, and emits
//! RawFeatures when a window closes.

use plumbum_core::dns::DnsRecord;
use plumbum_core::features::{compute_beacon_features, extract_base_domain, shannon_entropy};
use plumbum_score::normalize::RawFeatures;
use std::collections::{HashMap, HashSet};

/// Per-domain accumulation state within a window.
#[derive(Debug, Clone)]
pub struct DomainWindow {
    pub domain: String,
    pub timestamps: Vec<f64>,
    pub src_ips: HashSet<String>,
    pub subdomains: HashSet<String>,
    pub txt_lengths: Vec<usize>,
    pub query_names: Vec<String>,
    pub window_start: f64,
}

impl DomainWindow {
    pub fn new(domain: String, timestamp: f64) -> Self {
        Self {
            domain,
            timestamps: Vec::new(),
            src_ips: HashSet::new(),
            subdomains: HashSet::new(),
            txt_lengths: Vec::new(),
            query_names: Vec::new(),
            window_start: timestamp,
        }
    }

    /// Add a DNS record to this window.
    pub fn push(&mut self, record: &DnsRecord) {
        self.timestamps.push(record.timestamp);
        self.src_ips.insert(record.src_ip.clone());
        self.subdomains.insert(record.query_name.clone());
        self.query_names.push(record.query_name.clone());

        for ans in &record.answers {
            if ans.rtype == 16 {
                self.txt_lengths.push(ans.rdata.len());
            }
        }
    }

    /// Convert accumulated data to RawFeatures for scoring.
    pub fn to_raw_features(&self, c2_suffixes: &[String]) -> RawFeatures {
        let mean_entropy = if self.query_names.is_empty() {
            0.0
        } else {
            let total: f64 = self
                .query_names
                .iter()
                .map(|q| {
                    let labels: Vec<&str> = q.split('.').collect();
                    if labels.len() > 2 {
                        shannon_entropy(labels[0].as_bytes())
                    } else {
                        shannon_entropy(q.as_bytes())
                    }
                })
                .sum();
            total / self.query_names.len() as f64
        };

        let cv = {
            let mut ts = self.timestamps.clone();
            compute_beacon_features(&mut ts)
                .map(|bf| bf.cv)
                .unwrap_or(2.0)
        };

        let mean_txt_length = if self.txt_lengths.is_empty() {
            0.0
        } else {
            self.txt_lengths.iter().sum::<usize>() as f64 / self.txt_lengths.len() as f64
        };

        let is_c2 = c2_suffixes
            .iter()
            .any(|s| self.domain == *s || self.domain.ends_with(&format!(".{}", s)));

        RawFeatures {
            domain: self.domain.clone(),
            is_c2,
            mean_entropy,
            cv,
            query_count: self.timestamps.len(),
            mean_txt_length,
            client_count: self.src_ips.len(),
            subdomain_count: self.subdomains.len(),
        }
    }
}

/// Manages sliding windows across all observed domains.
pub struct WindowAccumulator {
    /// Window duration in seconds.
    pub window_secs: f64,
    /// Known C2 domain suffixes.
    pub c2_suffixes: Vec<String>,
    /// Active windows keyed by base domain.
    windows: HashMap<String, DomainWindow>,
}

impl WindowAccumulator {
    pub fn new(window_secs: f64, c2_suffixes: Vec<String>) -> Self {
        Self {
            window_secs,
            c2_suffixes,
            windows: HashMap::new(),
        }
    }

    /// Ingest a DNS record. Returns expired domain features if any
    /// windows have closed due to this record's timestamp.
    pub fn push(&mut self, record: &DnsRecord) -> Vec<RawFeatures> {
        let base = extract_base_domain(&record.query_name, &self.c2_suffixes);

        let expired = self.flush_expired(record.timestamp);

        let window = self
            .windows
            .entry(base.clone())
            .or_insert_with(|| DomainWindow::new(base, record.timestamp));
        window.push(record);

        expired
    }

    /// Flush all windows whose start + window_secs <= now.
    fn flush_expired(&mut self, now: f64) -> Vec<RawFeatures> {
        let mut expired = Vec::new();
        let mut to_remove = Vec::new();

        for (domain, window) in &self.windows {
            if now - window.window_start >= self.window_secs {
                expired.push(window.to_raw_features(&self.c2_suffixes));
                to_remove.push(domain.clone());
            }
        }

        for domain in to_remove {
            self.windows.remove(&domain);
        }

        expired
    }

    /// Force-flush all active windows (e.g., at shutdown).
    pub fn flush_all(&mut self) -> Vec<RawFeatures> {
        let features: Vec<RawFeatures> = self
            .windows
            .values()
            .map(|w| w.to_raw_features(&self.c2_suffixes))
            .collect();
        self.windows.clear();
        features
    }

    /// Number of active domain windows.
    pub fn active_count(&self) -> usize {
        self.windows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plumbum_core::dns::DnsRecord;

    fn make_record(domain: &str, src_ip: &str, ts: f64) -> DnsRecord {
        DnsRecord {
            timestamp: ts,
            src_ip: src_ip.to_string(),
            src_port: 12345,
            dst_ip: "8.8.8.8".to_string(),
            dst_port: 53,
            proto: "UDP".to_string(),
            trans_id: 1,
            query_name: domain.to_string(),
            query_type: 16,
            query_type_name: "TXT".to_string(),
            rcode: 0,
            rcode_name: "NOERROR".to_string(),
            is_response: false,
            answers: vec![],
        }
    }

    #[test]
    fn test_window_expiry() {
        let mut acc = WindowAccumulator::new(10.0, vec!["evil.tk".to_string()]);

        let r1 = make_record("sub1.evil.tk", "10.0.0.1", 100.0);
        let r2 = make_record("sub2.evil.tk", "10.0.0.2", 105.0);
        assert!(acc.push(&r1).is_empty());
        assert!(acc.push(&r2).is_empty());

        let r3 = make_record("sub3.evil.tk", "10.0.0.1", 111.0);
        let expired = acc.push(&r3);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].domain, "evil.tk");
        assert_eq!(expired[0].query_count, 2);
        assert_eq!(expired[0].client_count, 2);
    }

    #[test]
    fn test_flush_all() {
        let mut acc = WindowAccumulator::new(60.0, vec![]);
        let r1 = make_record("test.example.com", "10.0.0.1", 100.0);
        acc.push(&r1);
        let all = acc.flush_all();
        assert_eq!(all.len(), 1);
        assert_eq!(acc.active_count(), 0);
    }
}
