use std::path::Path;

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let plumbum_dir = Path::new(".plumbum");
    if !plumbum_dir.exists() {
        return Err("No .plumbum/ directory. Run 'plumbum init' first.".into());
    }

    let conn = plumbum_store::schema::open_db(plumbum_dir)?;
    let run_id = plumbum_store::query::get_latest_run(&conn)?
        .ok_or("No runs found. Run 'plumbum apply' first.")?;

    let domains = plumbum_store::query::get_scored_domains(&conn, run_id)?;

    let mut app = plumbum_tui::app::App::new(domains, run_id);
    app.run()?;

    Ok(())
}
