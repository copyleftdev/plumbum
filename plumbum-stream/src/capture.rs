//! Live packet capture via libpcap.
//!
//! Opens a network interface, applies a BPF filter for DNS (port 53),
//! and yields parsed DnsRecord values.

use pcap::{Capture, Device};
use plumbum_core::dns::DnsRecord;
use plumbum_core::pcap::{parse_ipv4_dns, parse_packet, parse_sll_packet};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

/// Datalink type constants matching libpcap.
const DLT_EN10MB: i32 = 1;
const DLT_LINUX_SLL: i32 = 113;
const DLT_RAW: i32 = 12;

/// Configuration for live capture.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Network interface name (e.g., "eth0", "en0").
    pub interface: String,
    /// BPF filter (default: "port 53").
    pub bpf_filter: String,
    /// Snap length in bytes.
    pub snaplen: i32,
    /// Promiscuous mode.
    pub promisc: bool,
    /// Read timeout in milliseconds.
    pub timeout_ms: i32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            bpf_filter: "port 53".to_string(),
            snaplen: 65535,
            promisc: true,
            timeout_ms: 100,
        }
    }
}

/// List available network interfaces.
pub fn list_interfaces() -> io::Result<Vec<String>> {
    let devices =
        Device::list().map_err(|e| io::Error::other(format!("pcap device list: {}", e)))?;
    Ok(devices.into_iter().map(|d| d.name).collect())
}

/// Start live capture. Calls `handler` for each parsed DNS record.
/// Blocks until `running` returns false or an error occurs.
pub fn capture_live<F>(
    config: &CaptureConfig,
    handler: &mut F,
    running: &dyn Fn() -> bool,
) -> io::Result<CaptureStats>
where
    F: FnMut(DnsRecord),
{
    let mut cap = Capture::from_device(config.interface.as_str())
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("interface: {}", e)))?
        .snaplen(config.snaplen)
        .promisc(config.promisc)
        .timeout(config.timeout_ms)
        .open()
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("open: {}", e)))?;

    cap.filter(&config.bpf_filter, true)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bpf: {}", e)))?;

    let link_type = cap.get_datalink();
    let dlt = link_type.0;

    if dlt != DLT_EN10MB && dlt != DLT_LINUX_SLL && dlt != DLT_RAW {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "Unsupported datalink type: {} (need Ethernet/1, SLL/113, or Raw/12)",
                dlt
            ),
        ));
    }

    let mut stats = CaptureStats::default();

    while running() {
        match cap.next_packet() {
            Ok(packet) => {
                stats.packets_seen += 1;
                let timestamp = now_epoch();
                let record = match dlt {
                    DLT_EN10MB => parse_packet(packet.data, timestamp),
                    DLT_LINUX_SLL => parse_sll_packet(packet.data, timestamp),
                    DLT_RAW => parse_ipv4_dns(packet.data, timestamp),
                    _ => None,
                };
                if let Some(rec) = record {
                    stats.dns_records += 1;
                    if rec.query_type == 16 {
                        stats.txt_records += 1;
                    }
                    handler(rec);
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                return Err(io::Error::other(format!("capture: {}", e)));
            }
        }
    }

    Ok(stats)
}

/// Statistics from a live capture session.
#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    pub packets_seen: u64,
    pub dns_records: u64,
    pub txt_records: u64,
}

fn now_epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
