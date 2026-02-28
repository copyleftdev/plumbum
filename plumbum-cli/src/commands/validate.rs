use std::path::PathBuf;

pub fn run(paths: &[PathBuf]) -> Result<(), Box<dyn std::error::Error>> {
    for path in paths {
        if !path.exists() {
            return Err(format!("File not found: {}", path.display()).into());
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let path_str = path.to_string_lossy().to_lowercase();

        let source_type = if ext == "pcap" || ext == "pcapng" || path_str.contains(".pcap") {
            "pcap"
        } else if ext == "log" || path_str.contains("dns") {
            "zeek"
        } else {
            "unknown"
        };

        match source_type {
            "pcap" => {
                let mut count = 0u64;
                let mut txt = 0u64;
                plumbum_core::pcap::parse_pcap(path, |rec| {
                    count += 1;
                    if rec.query_type == 16 {
                        txt += 1;
                    }
                })?;
                println!("  {} records parsed", count);
                println!("  {} TXT records", txt);
            }
            "zeek" => {
                let mut count = 0u64;
                let mut txt = 0u64;
                plumbum_core::zeek::parse_zeek_dns(path, |rec| {
                    count += 1;
                    if rec.query_type == 16 {
                        txt += 1;
                    }
                })?;
                println!("  {} records parsed", count);
                println!("  {} TXT records", txt);
            }
            _ => {
                return Err(format!("Unknown file format: {}", path.display()).into());
            }
        }
    }

    Ok(())
}
