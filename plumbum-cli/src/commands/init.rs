use std::path::Path;
use plumbum_config::defaults::DEFAULT_CONFIG_HCL;

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let plumbum_dir = Path::new(".plumbum");

    if plumbum_dir.exists() {
        eprintln!(".plumbum/ already exists");
        return Ok(());
    }

    std::fs::create_dir_all(plumbum_dir)?;

    // Write default config
    std::fs::write(plumbum_dir.join("config.hcl"), DEFAULT_CONFIG_HCL)?;

    // Initialize database
    plumbum_store::schema::open_db(plumbum_dir)?;

    println!("Initialized .plumbum/");
    println!("  config.hcl  (analysis weights and thresholds)");
    println!("  plumbum.db  (SQLite database)");

    Ok(())
}
