//! Plumbum CLI — Deterministic DNS TXT Analysis
//!
//! plumbum <command> [arguments] [flags]

use std::path::PathBuf;
use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(
    name = "plumbum",
    about = "Deterministic DNS TXT Analysis",
    long_about = "Plumbum measures the depth of DNS.\n\nIt does not guess. It computes.\nIt does not alert. It explains.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize working directory (.plumbum/)
    Init,

    /// Validate input log structure and field consistency
    Validate {
        /// Path to dns.log or PCAP file(s)
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },

    /// Dry run: show what will be analyzed without scoring
    Plan {
        /// Path to dns.log or PCAP file(s)
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },

    /// Perform full analysis and scoring
    Apply {
        /// Path to dns.log or PCAP file(s)
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Known C2 domains for labeling (optional)
        #[arg(long)]
        c2_domains: Vec<String>,

        /// Weight preset: default, optimized, regularized
        #[arg(long, default_value = "regularized")]
        weights: String,
    },

    /// Display structured result details for a domain
    Show {
        /// Domain name to inspect
        domain: String,
    },

    /// Deep score decomposition for a domain
    Explain {
        /// Domain name to explain
        domain: String,

        /// Specific feature to explain
        #[arg(long)]
        feature: Option<String>,
    },

    /// Export detections in various formats
    Export {
        /// Output format: json, csv, sigma
        #[arg(long, default_value = "json")]
        format: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Launch interactive TUI dashboard
    Dashboard,

    /// Print version information
    Version,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init => commands::init::run(),
        Commands::Validate { paths } => commands::validate::run(&paths),
        Commands::Plan { paths } => commands::plan::run(&paths),
        Commands::Apply { paths, c2_domains, weights } => {
            commands::apply::run(&paths, &c2_domains, &weights)
        }
        Commands::Show { domain } => commands::show::run(&domain),
        Commands::Explain { domain, feature } => commands::explain::run(&domain, feature.as_deref()),
        Commands::Export { format, output } => commands::export::run(&format, output.as_deref()),
        Commands::Dashboard => commands::dashboard::run(),
        Commands::Version => {
            println!("plumbum {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
