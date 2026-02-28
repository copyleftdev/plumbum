use std::path::Path;
use plumbum_score::normalize::DomainFeatures;
use plumbum_score::weights::Weights;
use plumbum_score::composite::score_domain;
use plumbum_score::explain;

pub fn run(domain: &str, _feature: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let plumbum_dir = Path::new(".plumbum");
    if !plumbum_dir.exists() {
        return Err("No .plumbum/ directory. Run 'plumbum init' first.".into());
    }

    let conn = plumbum_store::schema::open_db(plumbum_dir)?;
    let run_id = plumbum_store::query::get_latest_run(&conn)?
        .ok_or("No runs found. Run 'plumbum apply' first.")?;

    let row = plumbum_store::query::get_domain_score(&conn, run_id, domain)?
        .ok_or_else(|| format!("Domain '{}' not found in run #{}", domain, run_id))?;

    // Reconstruct features from DB row
    let features = DomainFeatures {
        domain: row.domain.clone(),
        is_c2: row.is_c2,
        entropy_norm: row.entropy_norm,
        periodicity_norm: row.periodicity_norm,
        volume_norm: row.volume_norm,
        length_norm: row.length_norm,
        client_rarity_norm: row.client_rarity_norm,
        subdomain_diversity_norm: row.subdomain_diversity_norm,
    };

    let weights = Weights::regularized();
    let scored = score_domain(&features, &weights);
    let expl = explain::explain(&scored, &weights);
    print!("{}", explain::format_explanation(&expl));

    Ok(())
}
