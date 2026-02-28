//! SQLite schema definition and migrations.
//!
//! The `.plumbum/` directory IS the database. Schema is versioned
//! and migrations are forward-only.

use rusqlite::{Connection, Result};

/// Current schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Initialize a new database with the full schema.
pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA synchronous=NORMAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS runs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT    NOT NULL DEFAULT (datetime('now')),
            finished_at TEXT,
            sources    TEXT,
            record_count INTEGER DEFAULT 0,
            txt_count    INTEGER DEFAULT 0,
            status     TEXT    NOT NULL DEFAULT 'running'
        );

        CREATE TABLE IF NOT EXISTS dns_records (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id      INTEGER NOT NULL REFERENCES runs(id),
            timestamp   REAL    NOT NULL,
            src_ip      TEXT    NOT NULL,
            src_port    INTEGER NOT NULL,
            dst_ip      TEXT    NOT NULL,
            dst_port    INTEGER NOT NULL,
            proto       TEXT    NOT NULL DEFAULT 'udp',
            trans_id    INTEGER NOT NULL,
            query_name  TEXT    NOT NULL,
            query_type  INTEGER NOT NULL,
            query_type_name TEXT NOT NULL,
            rcode       INTEGER NOT NULL,
            rcode_name  TEXT    NOT NULL,
            is_response INTEGER NOT NULL DEFAULT 0,
            answers_json TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_dns_query_name ON dns_records(query_name);
        CREATE INDEX IF NOT EXISTS idx_dns_query_type ON dns_records(query_type);
        CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_records(timestamp);
        CREATE INDEX IF NOT EXISTS idx_dns_run ON dns_records(run_id);

        CREATE TABLE IF NOT EXISTS domain_features (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id                  INTEGER NOT NULL REFERENCES runs(id),
            domain                  TEXT    NOT NULL,
            is_c2                   INTEGER NOT NULL DEFAULT 0,
            mean_entropy            REAL,
            cv                      REAL,
            query_count             INTEGER,
            mean_txt_length         REAL,
            client_count            INTEGER,
            subdomain_count         INTEGER,
            entropy_norm            REAL,
            periodicity_norm        REAL,
            volume_norm             REAL,
            length_norm             REAL,
            client_rarity_norm      REAL,
            subdomain_diversity_norm REAL,
            composite_score         REAL,
            severity                TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_feat_domain ON domain_features(domain);
        CREATE INDEX IF NOT EXISTS idx_feat_run ON domain_features(run_id);
        CREATE INDEX IF NOT EXISTS idx_feat_score ON domain_features(composite_score);
        "
    )?;

    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?1)",
        [SCHEMA_VERSION.to_string()],
    )?;

    Ok(())
}

/// Open or create the plumbum database in the given directory.
pub fn open_db(plumbum_dir: &std::path::Path) -> Result<Connection> {
    std::fs::create_dir_all(plumbum_dir).map_err(|e| {
        rusqlite::Error::InvalidParameterName(format!("Failed to create dir: {}", e))
    })?;

    let db_path = plumbum_dir.join("plumbum.db");
    let conn = Connection::open(&db_path)?;
    init_db(&conn)?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_db() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();

        let version: String = conn
            .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, "1");
    }
}
