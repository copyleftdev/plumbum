//! `plumbum stream` — Live network capture with real-time DNS anomaly scoring.

use plumbum_score::weights::Weights;
use plumbum_stream::accumulator::WindowAccumulator;
use plumbum_stream::capture::{capture_live, list_interfaces, CaptureConfig};
use plumbum_stream::scorer::{score_batch, ScorerConfig};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub fn run(
    interface: &str,
    window_secs: f64,
    threshold: f64,
    weights_preset: &str,
    c2_domains: &[String],
    list_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if list_only {
        let ifaces = list_interfaces()?;
        println!("Available interfaces:");
        for iface in &ifaces {
            let marker = if iface == interface {
                " (selected)"
            } else {
                ""
            };
            println!("  {}{}", iface, marker);
        }
        return Ok(());
    }

    let weights = match weights_preset {
        "optimized" => Weights::optimized(),
        "default" => Weights::default(),
        _ => Weights::regularized(),
    };

    let scorer_config = ScorerConfig {
        weights,
        alert_threshold: threshold,
        window_secs,
    };

    let mut accumulator = WindowAccumulator::new(window_secs, c2_domains.to_vec());

    let config = CaptureConfig {
        interface: interface.to_string(),
        ..Default::default()
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::Relaxed);
    })
    .expect("Failed to set Ctrl+C handler");

    eprintln!(
        "Streaming DNS from {} | window={}s threshold={} weights={}",
        interface, window_secs, threshold, weights_preset
    );
    eprintln!("Press Ctrl+C to stop.\n");

    let running_ref = running.clone();
    let mut handler = |record: plumbum_core::dns::DnsRecord| {
        let expired = accumulator.push(&record);
        if !expired.is_empty() {
            let alerts = score_batch(&expired, &scorer_config);
            for alert in &alerts {
                match serde_json::to_string(alert) {
                    Ok(json) => println!("{}", json),
                    Err(e) => eprintln!("json error: {}", e),
                }
            }
        }
    };

    let result = capture_live(&config, &mut handler, &|| {
        running_ref.load(Ordering::Relaxed)
    });

    let remaining = accumulator.flush_all();
    if !remaining.is_empty() {
        let alerts = score_batch(&remaining, &scorer_config);
        for alert in &alerts {
            if let Ok(json) = serde_json::to_string(alert) {
                println!("{}", json);
            }
        }
    }

    match result {
        Ok(stats) => {
            eprintln!(
                "\nCapture complete: packets={} dns={} txt={}",
                stats.packets_seen, stats.dns_records, stats.txt_records
            );
            Ok(())
        }
        Err(e) => Err(Box::new(e)),
    }
}
