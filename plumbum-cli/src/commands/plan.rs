use std::path::PathBuf;
use std::collections::HashSet;

pub fn run(paths: &[PathBuf]) -> Result<(), Box<dyn std::error::Error>> {
    let mut total_records = 0u64;
    let mut txt_records = 0u64;
    let mut domains = HashSet::new();
    let mut src_ips = HashSet::new();

    for path in paths {
        if !path.exists() {
            return Err(format!("File not found: {}", path.display()).into());
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let path_str = path.to_string_lossy().to_lowercase();

        let handler = |rec: plumbum_core::dns::DnsRecord| {
            total_records += 1;
            if rec.query_type == 16 { txt_records += 1; }
            domains.insert(rec.query_name.to_lowercase());
            src_ips.insert(rec.src_ip.clone());
        };

        if ext == "pcap" || ext == "pcapng" || path_str.contains(".pcap") {
            plumbum_core::pcap::parse_pcap(path, handler)?;
        } else {
            plumbum_core::zeek::parse_zeek_dns(path, handler)?;
        }
    }

    println!("Plumbum will perform:\n");
    println!("- TXT entropy modeling");
    println!("- Periodicity modeling");
    println!("- Domain rarity scoring");
    println!("- Subdomain diversity scoring");
    println!("- Host baseline deviation\n");
    println!("Records:      {}", total_records);
    println!("TXT responses: {}", txt_records);
    println!("Distinct domains: {}", domains.len());
    println!("Source hosts: {}", src_ips.len());

    Ok(())
}
