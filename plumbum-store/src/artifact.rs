//! Run artifact I/O (JSON export of features, summary, etc.)

use std::path::Path;
use std::io::Write;

use crate::query::{DomainScoreRow, RunSummary};

/// Write a JSON summary of a run to a file.
pub fn write_summary_json(path: &Path, summary: &RunSummary) -> std::io::Result<()> {
    let json = format!(
        concat!(
            "{{\n",
            "  \"run_id\": {},\n",
            "  \"total_records\": {},\n",
            "  \"txt_records\": {},\n",
            "  \"domains_scored\": {},\n",
            "  \"critical\": {},\n",
            "  \"high\": {},\n",
            "  \"medium\": {}\n",
            "}}\n"
        ),
        summary.run_id, summary.total_records, summary.txt_records,
        summary.domain_count, summary.critical_count, summary.high_count,
        summary.medium_count,
    );
    let mut f = std::fs::File::create(path)?;
    f.write_all(json.as_bytes())
}

/// Write scored domains as JSON array.
pub fn write_domains_json(path: &Path, domains: &[DomainScoreRow]) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(b"[\n")?;
    for (i, d) in domains.iter().enumerate() {
        let comma = if i + 1 < domains.len() { "," } else { "" };
        let line = format!(
            "  {{\"domain\":\"{}\",\"score\":{:.1},\"severity\":\"{}\",\"entropy\":{:.3},\"cv\":{:.3},\"queries\":{},\"clients\":{},\"subdomains\":{}}}{}",
            d.domain, d.composite_score, d.severity,
            d.mean_entropy, d.cv, d.query_count, d.client_count, d.subdomain_count,
            comma,
        );
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
    }
    f.write_all(b"]\n")
}

/// Write scored domains as CSV.
pub fn write_domains_csv(path: &Path, domains: &[DomainScoreRow]) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(b"domain,score,severity,entropy,cv,queries,clients,subdomains\n")?;
    for d in domains {
        let line = format!(
            "{},{:.1},{},{:.3},{:.3},{},{},{}\n",
            d.domain, d.composite_score, d.severity,
            d.mean_entropy, d.cv, d.query_count, d.client_count, d.subdomain_count,
        );
        f.write_all(line.as_bytes())?;
    }
    Ok(())
}
