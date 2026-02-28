//! Prepared statement wrappers for reading analysis results.

use rusqlite::{params, Connection, Result};

/// A domain score row from the database.
#[derive(Debug, Clone)]
pub struct DomainScoreRow {
    pub domain: String,
    pub composite_score: f64,
    pub severity: String,
    pub is_c2: bool,
    pub mean_entropy: f64,
    pub cv: f64,
    pub query_count: i64,
    pub mean_txt_length: f64,
    pub client_count: i64,
    pub subdomain_count: i64,
    pub entropy_norm: f64,
    pub periodicity_norm: f64,
    pub volume_norm: f64,
    pub length_norm: f64,
    pub client_rarity_norm: f64,
    pub subdomain_diversity_norm: f64,
}

/// Get all scored domains for a run, ordered by score descending.
pub fn get_scored_domains(conn: &Connection, run_id: i64) -> Result<Vec<DomainScoreRow>> {
    let mut stmt = conn.prepare(
        "SELECT domain, composite_score, severity, is_c2, mean_entropy, cv, query_count, mean_txt_length, client_count, subdomain_count, entropy_norm, periodicity_norm, volume_norm, length_norm, client_rarity_norm, subdomain_diversity_norm FROM domain_features WHERE run_id=?1 ORDER BY composite_score DESC"
    )?;

    let rows = stmt.query_map([run_id], |row| {
        Ok(DomainScoreRow {
            domain: row.get(0)?,
            composite_score: row.get(1)?,
            severity: row.get(2)?,
            is_c2: row.get::<_, i64>(3)? != 0,
            mean_entropy: row.get(4)?,
            cv: row.get(5)?,
            query_count: row.get(6)?,
            mean_txt_length: row.get(7)?,
            client_count: row.get(8)?,
            subdomain_count: row.get(9)?,
            entropy_norm: row.get(10)?,
            periodicity_norm: row.get(11)?,
            volume_norm: row.get(12)?,
            length_norm: row.get(13)?,
            client_rarity_norm: row.get(14)?,
            subdomain_diversity_norm: row.get(15)?,
        })
    })?;

    rows.collect()
}

/// Get a single domain's score by name and run.
pub fn get_domain_score(
    conn: &Connection,
    run_id: i64,
    domain: &str,
) -> Result<Option<DomainScoreRow>> {
    let mut stmt = conn.prepare(
        "SELECT domain, composite_score, severity, is_c2, mean_entropy, cv, query_count, mean_txt_length, client_count, subdomain_count, entropy_norm, periodicity_norm, volume_norm, length_norm, client_rarity_norm, subdomain_diversity_norm FROM domain_features WHERE run_id=?1 AND domain=?2"
    )?;

    let mut rows = stmt.query_map(params![run_id, domain], |row| {
        Ok(DomainScoreRow {
            domain: row.get(0)?,
            composite_score: row.get(1)?,
            severity: row.get(2)?,
            is_c2: row.get::<_, i64>(3)? != 0,
            mean_entropy: row.get(4)?,
            cv: row.get(5)?,
            query_count: row.get(6)?,
            mean_txt_length: row.get(7)?,
            client_count: row.get(8)?,
            subdomain_count: row.get(9)?,
            entropy_norm: row.get(10)?,
            periodicity_norm: row.get(11)?,
            volume_norm: row.get(12)?,
            length_norm: row.get(13)?,
            client_rarity_norm: row.get(14)?,
            subdomain_diversity_norm: row.get(15)?,
        })
    })?;

    match rows.next() {
        Some(Ok(row)) => Ok(Some(row)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// Get the latest run ID.
pub fn get_latest_run(conn: &Connection) -> Result<Option<i64>> {
    conn.query_row("SELECT id FROM runs ORDER BY id DESC LIMIT 1", [], |row| {
        row.get(0)
    })
    .optional()
}

/// Re-export optional helper.
trait Optional<T> {
    fn optional(self) -> Result<Option<T>>;
}

impl<T> Optional<T> for Result<T> {
    fn optional(self) -> Result<Option<T>> {
        match self {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Summary stats for a run.
#[derive(Debug, Clone)]
pub struct RunSummary {
    pub run_id: i64,
    pub total_records: i64,
    pub txt_records: i64,
    pub domain_count: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
}

/// Get summary statistics for a run.
pub fn get_run_summary(conn: &Connection, run_id: i64) -> Result<RunSummary> {
    let total_records: i64 =
        conn.query_row("SELECT record_count FROM runs WHERE id=?1", [run_id], |r| {
            r.get(0)
        })?;
    let txt_records: i64 =
        conn.query_row("SELECT txt_count FROM runs WHERE id=?1", [run_id], |r| {
            r.get(0)
        })?;
    let domain_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM domain_features WHERE run_id=?1",
        [run_id],
        |r| r.get(0),
    )?;
    let critical_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM domain_features WHERE run_id=?1 AND severity='CRITICAL'",
        [run_id],
        |r| r.get(0),
    )?;
    let high_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM domain_features WHERE run_id=?1 AND severity='HIGH'",
        [run_id],
        |r| r.get(0),
    )?;
    let medium_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM domain_features WHERE run_id=?1 AND severity='MEDIUM'",
        [run_id],
        |r| r.get(0),
    )?;

    Ok(RunSummary {
        run_id,
        total_records,
        txt_records,
        domain_count,
        critical_count,
        high_count,
        medium_count,
    })
}
