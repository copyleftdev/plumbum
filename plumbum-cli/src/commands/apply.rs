use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use plumbum_core::dns::DnsRecord;
use plumbum_core::features;
use plumbum_score::composite;
use plumbum_score::normalize::{self, CorpusStats, DomainFeatures, RawFeatures};
use plumbum_score::weights::Weights;
use plumbum_store::schema;
use plumbum_store::ingest;

struct DomainAccum {
    timestamps: Vec<f64>,
    txt_contents: Vec<String>,
    src_ips: HashSet<String>,
    subdomains: HashSet<String>,
    query_count: usize,
    txt_lengths: Vec<usize>,
}

pub fn run(
    paths: &[PathBuf],
    c2_domains: &[String],
    weight_preset: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let plumbum_dir = Path::new(".plumbum");
    if !plumbum_dir.exists() {
        return Err("No .plumbum/ directory. Run 'plumbum init' first.".into());
    }

    let conn = schema::open_db(plumbum_dir)?;
    let sources_str = paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ");
    let run_id = ingest::create_run(&conn, &sources_str)?;

    let c2_suffixes: Vec<String> = c2_domains.iter().map(|d| d.to_lowercase()).collect();

    // Accumulate per-domain data
    let mut domain_map: HashMap<String, DomainAccum> = HashMap::new();
    let mut all_records: Vec<DnsRecord> = Vec::new();
    let mut record_count = 0u64;
    let mut txt_count = 0u64;

    for path in paths {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let path_str = path.to_string_lossy().to_lowercase();

        let mut batch: Vec<DnsRecord> = Vec::new();

        let handler = |rec: DnsRecord| {
            batch.push(rec);
        };

        if ext == "pcap" || ext == "pcapng" || path_str.contains(".pcap") {
            plumbum_core::pcap::parse_pcap(path, handler)?;
        } else {
            plumbum_core::zeek::parse_zeek_dns(path, handler)?;
        }

        for rec in &batch {
            record_count += 1;
            if rec.query_type == 16 { txt_count += 1; }

            if !rec.is_response { continue; }

            let base = features::extract_base_domain(&rec.query_name, &c2_suffixes);
            let acc = domain_map.entry(base.clone()).or_insert_with(|| DomainAccum {
                timestamps: Vec::new(),
                txt_contents: Vec::new(),
                src_ips: HashSet::new(),
                subdomains: HashSet::new(),
                query_count: 0,
                txt_lengths: Vec::new(),
            });

            acc.timestamps.push(rec.timestamp);
            acc.src_ips.insert(rec.src_ip.clone());
            acc.subdomains.insert(rec.query_name.to_lowercase());
            acc.query_count += 1;

            for txt in rec.txt_answers() {
                acc.txt_contents.push(txt.to_string());
                acc.txt_lengths.push(txt.len());
            }
        }

        // Insert records in batches for DB persistence
        if !batch.is_empty() {
            ingest::insert_records(&conn, run_id, &batch)?;
            all_records.extend(batch);
        }
    }

    // Build raw features
    let mut raw_features: Vec<RawFeatures> = Vec::new();
    for (domain, acc) in &mut domain_map {
        let mean_entropy = if acc.txt_contents.is_empty() {
            0.0
        } else {
            let total: f64 = acc.txt_contents.iter()
                .map(|t| features::shannon_entropy(t.as_bytes()))
                .sum();
            total / acc.txt_contents.len() as f64
        };

        let cv = features::compute_beacon_features(&mut acc.timestamps)
            .map(|bf| bf.cv)
            .unwrap_or(2.0);

        let mean_txt_length = if acc.txt_lengths.is_empty() {
            0.0
        } else {
            acc.txt_lengths.iter().sum::<usize>() as f64 / acc.txt_lengths.len() as f64
        };

        let is_c2 = features::is_c2_domain(domain, &c2_suffixes);

        raw_features.push(RawFeatures {
            domain: domain.clone(),
            is_c2,
            mean_entropy,
            cv,
            query_count: acc.query_count,
            mean_txt_length,
            client_count: acc.src_ips.len(),
            subdomain_count: acc.subdomains.len(),
        });
    }

    // Normalize and score
    let stats = CorpusStats::from_raw(&raw_features);
    let norm_features: Vec<DomainFeatures> = raw_features.iter()
        .map(|r| normalize::normalize(r, &stats))
        .collect();

    let weights = match weight_preset {
        "optimized" => Weights::optimized(),
        "default" => Weights::default(),
        _ => Weights::regularized(),
    };

    let scored = composite::score_and_rank(&norm_features, &weights);

    // Persist scored domains
    for sd in &scored {
        let raw = raw_features.iter().find(|r| r.domain == sd.domain).unwrap();
        ingest::insert_scored_domain(&conn, run_id, sd, raw)?;
    }

    ingest::finish_run(&conn, run_id, record_count, txt_count)?;

    // Print findings
    println!("Plumbum Findings:\n");
    for sd in &scored {
        if sd.score >= 40.0 {
            println!("{:<8}  {:5.1}  {}", sd.severity.as_str(), sd.score, sd.domain);
        }
    }

    println!("\nArtifacts written to .plumbum/plumbum.db (run #{})", run_id);

    let summary = plumbum_store::query::get_run_summary(&conn, run_id)?;
    println!("\nSummary: {} domains scored, {} CRITICAL, {} HIGH, {} MEDIUM",
        summary.domain_count, summary.critical_count, summary.high_count, summary.medium_count);

    Ok(())
}
