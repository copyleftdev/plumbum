use std::path::Path;

pub fn run(format: &str, output: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    let plumbum_dir = Path::new(".plumbum");
    if !plumbum_dir.exists() {
        return Err("No .plumbum/ directory. Run 'plumbum init' first.".into());
    }

    let conn = plumbum_store::schema::open_db(plumbum_dir)?;
    let run_id = plumbum_store::query::get_latest_run(&conn)?
        .ok_or("No runs found. Run 'plumbum apply' first.")?;

    let domains = plumbum_store::query::get_scored_domains(&conn, run_id)?;

    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| Path::new(&format!("plumbum-export.{}", format)).to_path_buf());

    match format {
        "json" => {
            plumbum_store::artifact::write_domains_json(&out_path, &domains)?;
            println!(
                "Exported {} domains to {}",
                domains.len(),
                out_path.display()
            );
        }
        "csv" => {
            plumbum_store::artifact::write_domains_csv(&out_path, &domains)?;
            println!(
                "Exported {} domains to {}",
                domains.len(),
                out_path.display()
            );
        }
        "sigma" => {
            let critical: Vec<_> = domains
                .iter()
                .filter(|d| d.severity == "CRITICAL" || d.severity == "HIGH")
                .collect();
            let mut sigma = String::new();
            sigma.push_str("title: Plumbum DNS TXT Anomaly Detection\n");
            sigma.push_str("status: experimental\n");
            sigma.push_str("description: Domains flagged by Plumbum composite scoring\n");
            sigma.push_str("logsource:\n");
            sigma.push_str("  category: dns\n");
            sigma.push_str("detection:\n");
            sigma.push_str("  selection:\n");
            sigma.push_str("    query|endswith:\n");
            for d in &critical {
                sigma.push_str(&format!("      - '{}'\n", d.domain));
            }
            sigma.push_str("  condition: selection\n");
            sigma.push_str("level: high\n");
            std::fs::write(&out_path, &sigma)?;
            println!(
                "Exported {} flagged domains as Sigma rule to {}",
                critical.len(),
                out_path.display()
            );
        }
        _ => return Err(format!("Unknown format: {} (use json, csv, or sigma)", format).into()),
    }

    Ok(())
}
