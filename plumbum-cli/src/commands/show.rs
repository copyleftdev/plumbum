use std::path::Path;

pub fn run(domain: &str) -> Result<(), Box<dyn std::error::Error>> {
    let plumbum_dir = Path::new(".plumbum");
    if !plumbum_dir.exists() {
        return Err("No .plumbum/ directory. Run 'plumbum init' first.".into());
    }

    let conn = plumbum_store::schema::open_db(plumbum_dir)?;
    let run_id = plumbum_store::query::get_latest_run(&conn)?
        .ok_or("No runs found. Run 'plumbum apply' first.")?;

    let row = plumbum_store::query::get_domain_score(&conn, run_id, domain)?
        .ok_or_else(|| format!("Domain '{}' not found in run #{}", domain, run_id))?;

    println!("Domain: {}", row.domain);
    println!("Score:  {:.1} ({})\n", row.composite_score, row.severity);
    println!("Components:");
    println!("  {:<24} {:.3}", "Entropy (norm)", row.entropy_norm);
    println!("  {:<24} {:.3}", "Periodicity (norm)", row.periodicity_norm);
    println!("  {:<24} {:.3}", "Volume (norm)", row.volume_norm);
    println!("  {:<24} {:.3}", "Length (norm)", row.length_norm);
    println!("  {:<24} {:.3}", "Client Rarity (norm)", row.client_rarity_norm);
    println!("  {:<24} {:.3}", "Subdomain Div (norm)", row.subdomain_diversity_norm);
    println!("\nRaw Features:");
    println!("  Entropy:    {:.3} bits", row.mean_entropy);
    println!("  CV:         {:.3}", row.cv);
    println!("  Queries:    {}", row.query_count);
    println!("  TXT Length: {:.1}", row.mean_txt_length);
    println!("  Clients:    {}", row.client_count);
    println!("  Subdomains: {}", row.subdomain_count);

    Ok(())
}
