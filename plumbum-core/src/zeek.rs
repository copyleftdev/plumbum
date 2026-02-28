//! Zeek dns.log parser (TSV format).
//!
//! Parses Zeek's tab-separated dns.log files into `DnsRecord` values.
//! Handles the standard Zeek header lines (#separator, #set_separator,
//! #empty_field, #unset_field, #path, #open, #fields, #types, #close).

use std::io::{self, BufRead};
use std::path::Path;

use crate::dns::{DnsAnswer, DnsRecord, ParseStats};

/// Parse a Zeek dns.log file and call `handler` for each record.
pub fn parse_zeek_dns<P, F>(path: P, mut handler: F) -> io::Result<ParseStats>
where
    P: AsRef<Path>,
    F: FnMut(DnsRecord),
{
    let file = std::fs::File::open(path)?;
    let reader = io::BufReader::with_capacity(1 << 20, file);

    let mut stats = ParseStats::default();
    let mut field_names: Vec<String> = Vec::new();
    let mut separator = '\t';
    let mut set_separator = ',';
    let mut empty_field = "(empty)".to_string();
    let mut unset_field = "-".to_string();

    for line_result in reader.lines() {
        let line = line_result?;

        if line.starts_with("#separator") {
            if let Some(sep_spec) = line.strip_prefix("#separator ") {
                separator = parse_separator_spec(sep_spec);
            }
            continue;
        }
        if line.starts_with("#set_separator") {
            if let Some(val) = line.split('\t').nth(1) {
                if let Some(c) = val.chars().next() {
                    set_separator = c;
                }
            }
            continue;
        }
        if line.starts_with("#empty_field") {
            if let Some(val) = line.split('\t').nth(1) {
                empty_field = val.to_string();
            }
            continue;
        }
        if line.starts_with("#unset_field") {
            if let Some(val) = line.split('\t').nth(1) {
                unset_field = val.to_string();
            }
            continue;
        }
        if line.starts_with("#fields") {
            field_names = line
                .split(separator)
                .skip(1)
                .map(|s| s.to_string())
                .collect();
            continue;
        }
        if line.starts_with('#') {
            continue;
        }

        if field_names.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split(separator).collect();
        if fields.len() < field_names.len() {
            stats.errors += 1;
            continue;
        }

        stats.total_packets += 1;

        let get = |name: &str| -> Option<&str> {
            field_names.iter().position(|n| n == name).and_then(|i| {
                let val = fields.get(i).copied().unwrap_or(&unset_field);
                if val == unset_field || val == empty_field {
                    None
                } else {
                    Some(val)
                }
            })
        };

        let timestamp = match get("ts").and_then(|v| v.parse::<f64>().ok()) {
            Some(ts) => ts,
            None => {
                stats.errors += 1;
                continue;
            }
        };

        let src_ip = get("id.orig_h").unwrap_or("0.0.0.0").to_string();
        let src_port = get("id.orig_p").and_then(|v| v.parse().ok()).unwrap_or(0);
        let dst_ip = get("id.resp_h").unwrap_or("0.0.0.0").to_string();
        let dst_port = get("id.resp_p").and_then(|v| v.parse().ok()).unwrap_or(53);
        let proto = get("proto").unwrap_or("udp").to_string();
        let trans_id = get("trans_id").and_then(|v| v.parse().ok()).unwrap_or(0);
        let query_name = get("query").unwrap_or("").to_string();
        let query_type_name = get("qtype_name").unwrap_or("").to_string();
        let query_type = get("qtype")
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| qtype_name_to_num(&query_type_name));
        let rcode = get("rcode").and_then(|v| v.parse().ok()).unwrap_or(0);
        let rcode_name = get("rcode_name").unwrap_or("NOERROR").to_string();

        // QR field: Zeek uses "T"/"F" for booleans
        let is_response = get("QR").map(|v| v == "T" || v == "true").unwrap_or(false);

        // Parse answers: comma-separated values
        let answers = match get("answers") {
            Some(ans_str) => ans_str
                .split(set_separator)
                .filter(|a| !a.is_empty())
                .map(|rdata| DnsAnswer {
                    rtype: query_type,
                    rtype_name: query_type_name.clone(),
                    rdata: rdata.to_string(),
                    ttl: get("TTLs")
                        .and_then(|t| t.split(set_separator).next())
                        .and_then(|t| t.parse::<f64>().ok())
                        .map(|t| t as u32)
                        .unwrap_or(0),
                })
                .collect(),
            None => Vec::new(),
        };

        let record = DnsRecord {
            timestamp,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            proto,
            trans_id,
            query_name,
            query_type,
            query_type_name,
            rcode,
            rcode_name,
            is_response,
            answers,
        };

        stats.dns_records += 1;
        if record.is_response {
            stats.responses += 1;
        }
        if record.is_txt() {
            stats.txt_records += 1;
        }

        handler(record);
    }

    Ok(stats)
}

/// Parse Zeek's separator specification.
/// Zeek encodes the separator as `\x09` for tab, etc.
fn parse_separator_spec(spec: &str) -> char {
    if let Some(hex) = spec.strip_prefix("\\x") {
        if let Ok(byte) = u8::from_str_radix(hex, 16) {
            return byte as char;
        }
    }
    spec.chars().next().unwrap_or('\t')
}

/// Convert query type name to numeric value.
fn qtype_name_to_num(name: &str) -> u16 {
    match name {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "ANY" => 255,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_separator_spec() {
        assert_eq!(parse_separator_spec("\\x09"), '\t');
        assert_eq!(parse_separator_spec(","), ',');
    }

    #[test]
    fn test_qtype_name_to_num() {
        assert_eq!(qtype_name_to_num("A"), 1);
        assert_eq!(qtype_name_to_num("TXT"), 16);
        assert_eq!(qtype_name_to_num("AAAA"), 28);
        assert_eq!(qtype_name_to_num("UNKNOWN"), 0);
    }
}
