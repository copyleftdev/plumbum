//! DNS record types and shared data structures.
//!
//! These types are the lingua franca of Plumbum. Every parser (Zeek, PCAP)
//! produces `DnsRecord` values. Every downstream consumer (store, score, TUI)
//! reads them.

use std::fmt;

/// Severity level for scored domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_score(score: f64) -> Self {
        if score >= 80.0 {
            Severity::Critical
        } else if score >= 60.0 {
            Severity::High
        } else if score >= 40.0 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }

    pub fn threshold(&self) -> f64 {
        match self {
            Severity::Critical => 80.0,
            Severity::High => 60.0,
            Severity::Medium => 40.0,
            Severity::Low => 0.0,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single DNS answer record extracted from a response.
#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub rtype: u16,
    pub rtype_name: String,
    pub rdata: String,
    pub ttl: u32,
}

/// A parsed DNS record from any source (Zeek log, PCAP, pcapng).
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub timestamp: f64,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    pub trans_id: u16,
    pub query_name: String,
    pub query_type: u16,
    pub query_type_name: String,
    pub rcode: u8,
    pub rcode_name: String,
    pub is_response: bool,
    pub answers: Vec<DnsAnswer>,
}

impl DnsRecord {
    /// Returns the first TXT answer content, if any.
    pub fn first_txt(&self) -> Option<&str> {
        self.answers
            .iter()
            .find(|a| a.rtype == 16)
            .map(|a| a.rdata.as_str())
    }

    /// Returns all TXT answer contents.
    pub fn txt_answers(&self) -> Vec<&str> {
        self.answers
            .iter()
            .filter(|a| a.rtype == 16)
            .map(|a| a.rdata.as_str())
            .collect()
    }

    /// True if this is a TXT query or response.
    pub fn is_txt(&self) -> bool {
        self.query_type == 16
    }

    /// True if rcode indicates NXDOMAIN.
    pub fn is_nxdomain(&self) -> bool {
        self.rcode == 3
    }
}

/// Map DNS RCODE numeric value to name.
pub fn rcode_to_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

/// Map DNS query type numeric value to name.
pub fn qtype_to_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "OTHER",
    }
}

/// Input source type for provenance tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSource {
    ZeekTsv(String),
    ZeekJson(String),
    Pcap(String),
    Pcapng(String),
}

impl fmt::Display for InputSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputSource::ZeekTsv(p) => write!(f, "zeek-tsv:{}", p),
            InputSource::ZeekJson(p) => write!(f, "zeek-json:{}", p),
            InputSource::Pcap(p) => write!(f, "pcap:{}", p),
            InputSource::Pcapng(p) => write!(f, "pcapng:{}", p),
        }
    }
}

/// Statistics from a parsing run.
#[derive(Debug, Clone, Default)]
pub struct ParseStats {
    pub total_packets: u64,
    pub dns_records: u64,
    pub responses: u64,
    pub txt_records: u64,
    pub errors: u64,
}

impl fmt::Display for ParseStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "packets={} dns={} responses={} txt={} errors={}",
            self.total_packets, self.dns_records, self.responses,
            self.txt_records, self.errors
        )
    }
}
