//! Batch record ingestion into SQLite.

use plumbum_core::dns::DnsRecord;
use rusqlite::{params, Connection, Result};

/// Create a new run and return its ID.
pub fn create_run(conn: &Connection, sources: &str) -> Result<i64> {
    conn.execute("INSERT INTO runs (sources) VALUES (?1)", [sources])?;
    Ok(conn.last_insert_rowid())
}

/// Finish a run, setting its status and final counts.
pub fn finish_run(conn: &Connection, run_id: i64, record_count: u64, txt_count: u64) -> Result<()> {
    conn.execute(
        "UPDATE runs SET finished_at=datetime('now'), status='complete', record_count=?1, txt_count=?2 WHERE id=?3",
        params![record_count as i64, txt_count as i64, run_id],
    )?;
    Ok(())
}

/// Insert a batch of DNS records. Uses a transaction for performance.
pub fn insert_records(conn: &Connection, run_id: i64, records: &[DnsRecord]) -> Result<()> {
    let tx = conn.unchecked_transaction()?;

    {
        let mut stmt = tx.prepare_cached(
            "INSERT INTO dns_records (run_id, timestamp, src_ip, src_port, dst_ip, dst_port, proto, trans_id, query_name, query_type, query_type_name, rcode, rcode_name, is_response, answers_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)"
        )?;

        for rec in records {
            let answers_json =
                if rec.answers.is_empty() {
                    None
                } else {
                    let answers: Vec<String> = rec.answers.iter().map(|a| {
                    format!("{{\"rtype\":{},\"rtype_name\":\"{}\",\"rdata\":\"{}\",\"ttl\":{}}}",
                        a.rtype,
                        a.rtype_name.replace('\"', "\\\""),
                        a.rdata.replace('\"', "\\\""),
                        a.ttl)
                }).collect();
                    Some(format!("[{}]", answers.join(",")))
                };

            stmt.execute(params![
                run_id,
                rec.timestamp,
                rec.src_ip,
                rec.src_port as i64,
                rec.dst_ip,
                rec.dst_port as i64,
                rec.proto,
                rec.trans_id as i64,
                rec.query_name,
                rec.query_type as i64,
                rec.query_type_name,
                rec.rcode as i64,
                rec.rcode_name,
                rec.is_response as i64,
                answers_json,
            ])?;
        }
    }

    tx.commit()?;
    Ok(())
}

/// Insert scored domain features for a run.
pub fn insert_scored_domain(
    conn: &Connection,
    run_id: i64,
    scored: &plumbum_score::composite::ScoredDomain,
    raw: &plumbum_score::normalize::RawFeatures,
) -> Result<()> {
    conn.execute(
        "INSERT INTO domain_features (run_id, domain, is_c2, mean_entropy, cv, query_count, mean_txt_length, client_count, subdomain_count, entropy_norm, periodicity_norm, volume_norm, length_norm, client_rarity_norm, subdomain_diversity_norm, composite_score, severity) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
        params![
            run_id,
            scored.domain,
            scored.is_c2 as i64,
            raw.mean_entropy,
            raw.cv,
            raw.query_count as i64,
            raw.mean_txt_length,
            raw.client_count as i64,
            raw.subdomain_count as i64,
            scored.features.entropy_norm,
            scored.features.periodicity_norm,
            scored.features.volume_norm,
            scored.features.length_norm,
            scored.features.client_rarity_norm,
            scored.features.subdomain_diversity_norm,
            scored.score,
            scored.severity.as_str(),
        ],
    )?;
    Ok(())
}
