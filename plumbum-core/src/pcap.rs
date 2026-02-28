//! PCAP/pcapng + DNS wire-format parser.
//!
//! Parses PCAP and pcapng files containing Ethernet/IP/UDP/DNS traffic and
//! extracts DNS query/response records with full answer data. No external deps.
//!
//! Supports:
//! - PCAP format (classic libpcap, both endianness, micro/nanosecond)
//! - pcapng format (Section Header / Interface Description / Enhanced Packet)
//! - Ethernet II link layer (type 1)
//! - IPv4 (protocol 17 = UDP)
//! - DNS over UDP port 53
//! - Standard DNS wire format with label compression
//! - TXT, A, AAAA, CNAME, MX, NS, PTR answer records

use std::io::{self, Read};
use std::path::Path;

use crate::dns::{self, DnsAnswer, DnsRecord, ParseStats};

const PCAP_MAGIC_LE: u32 = 0xa1b2c3d4;
const PCAP_MAGIC_BE: u32 = 0xd4c3b2a1;
const PCAP_MAGIC_NS_LE: u32 = 0xa1b23c4d;
const PCAP_MAGIC_NS_BE: u32 = 0x4d3cb2a1;

const PCAPNG_SHB: u32 = 0x0a0d0d0a;
const PCAPNG_IDB: u32 = 0x00000001;
const PCAPNG_EPB: u32 = 0x00000006;
const PCAPNG_BYTE_ORDER_MAGIC: u32 = 0x1a2b3c4d;

const ETH_HEADER_LEN: usize = 14;
const SLL_HEADER_LEN: usize = 16;
const UDP_HEADER_LEN: usize = 8;
const DNS_HEADER_LEN: usize = 12;

struct PcapReader<R: Read> {
    reader: R,
    big_endian: bool,
    nanosecond: bool,
    link_type: u32,
}

impl<R: Read> PcapReader<R> {
    fn read_u16(&mut self) -> io::Result<u16> {
        let mut buf = [0u8; 2];
        self.reader.read_exact(&mut buf)?;
        Ok(if self.big_endian {
            u16::from_be_bytes(buf)
        } else {
            u16::from_le_bytes(buf)
        })
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(if self.big_endian {
            u32::from_be_bytes(buf)
        } else {
            u32::from_le_bytes(buf)
        })
    }

    fn read_bytes(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

/// Parse a PCAP or pcapng file and extract DNS records.
/// Calls `handler` for each successfully parsed DNS record.
pub fn parse_pcap<P, F>(path: P, mut handler: F) -> io::Result<ParseStats>
where
    P: AsRef<Path>,
    F: FnMut(DnsRecord),
{
    let file = std::fs::File::open(path)?;
    let mut reader = io::BufReader::with_capacity(1 << 20, file);

    let mut magic_buf = [0u8; 4];
    reader.read_exact(&mut magic_buf)?;
    let magic = u32::from_le_bytes(magic_buf);

    if magic == PCAPNG_SHB {
        parse_pcapng_inner(reader, magic_buf, &mut handler)
    } else {
        parse_pcap_classic(reader, magic, &mut handler)
    }
}

fn parse_pcap_classic<R, F>(reader: R, magic: u32, handler: &mut F) -> io::Result<ParseStats>
where
    R: Read,
    F: FnMut(DnsRecord),
{
    let (big_endian, nanosecond) = match magic {
        PCAP_MAGIC_LE => (false, false),
        PCAP_MAGIC_BE => (true, false),
        PCAP_MAGIC_NS_LE => (false, true),
        PCAP_MAGIC_NS_BE => (true, true),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid PCAP magic: 0x{:08x}", magic),
            ))
        }
    };

    let mut pcap = PcapReader {
        reader,
        big_endian,
        nanosecond,
        link_type: 0,
    };

    let _version_major = pcap.read_u16()?;
    let _version_minor = pcap.read_u16()?;
    let _thiszone = pcap.read_u32()?;
    let _sigfigs = pcap.read_u32()?;
    let _snaplen = pcap.read_u32()?;
    pcap.link_type = pcap.read_u32()?;

    if pcap.link_type != 1 && pcap.link_type != 113 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "Unsupported link type: {} (only Ethernet/1 and Linux SLL/113 supported)",
                pcap.link_type
            ),
        ));
    }

    let mut stats = ParseStats::default();

    loop {
        let ts_sec = match pcap.read_u32() {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };
        let ts_frac = pcap.read_u32()?;
        let incl_len = pcap.read_u32()? as usize;
        let _orig_len = pcap.read_u32()?;

        let timestamp = if pcap.nanosecond {
            ts_sec as f64 + ts_frac as f64 / 1_000_000_000.0
        } else {
            ts_sec as f64 + ts_frac as f64 / 1_000_000.0
        };

        stats.total_packets += 1;
        let data = pcap.read_bytes(incl_len)?;

        let record = if pcap.link_type == 113 {
            parse_sll_packet(&data, timestamp)
        } else {
            parse_packet(&data, timestamp)
        };
        if let Some(record) = record {
            update_stats(&record, &mut stats);
            handler(record);
        }
    }

    Ok(stats)
}

fn parse_pcapng_inner<R, F>(
    mut reader: R,
    _first_4: [u8; 4],
    handler: &mut F,
) -> io::Result<ParseStats>
where
    R: Read,
    F: FnMut(DnsRecord),
{
    let mut buf4 = [0u8; 4];

    reader.read_exact(&mut buf4)?;
    let shb_len = u32::from_le_bytes(buf4) as usize;

    reader.read_exact(&mut buf4)?;
    let bom = u32::from_le_bytes(buf4);
    let big_endian = bom != PCAPNG_BYTE_ORDER_MAGIC;

    let remaining = shb_len.saturating_sub(12);
    let mut skip_buf = vec![0u8; remaining];
    reader.read_exact(&mut skip_buf)?;

    let read_u32 = |buf: &[u8], be: bool| -> u32 {
        if be {
            u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])
        } else {
            u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
        }
    };
    let read_u16 = |buf: &[u8], be: bool| -> u16 {
        if be {
            u16::from_be_bytes([buf[0], buf[1]])
        } else {
            u16::from_le_bytes([buf[0], buf[1]])
        }
    };

    let mut link_type: u16 = 1;
    let mut ts_resol: f64 = 1_000_000.0;
    let mut stats = ParseStats::default();

    loop {
        let mut hdr = [0u8; 8];
        match reader.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }

        let block_type = read_u32(&hdr[0..4], big_endian);
        let block_len = read_u32(&hdr[4..8], big_endian) as usize;
        let body_len = block_len.saturating_sub(12);
        let mut body = vec![0u8; body_len];
        reader.read_exact(&mut body)?;

        let mut trail = [0u8; 4];
        reader.read_exact(&mut trail)?;

        match block_type {
            PCAPNG_IDB => {
                if body.len() >= 4 {
                    link_type = read_u16(&body[0..2], big_endian);
                    let mut opt_off = 8;
                    while opt_off + 4 <= body.len() {
                        let opt_code = read_u16(&body[opt_off..opt_off + 2], big_endian);
                        let opt_len =
                            read_u16(&body[opt_off + 2..opt_off + 4], big_endian) as usize;
                        opt_off += 4;
                        if opt_code == 0 {
                            break;
                        }
                        if opt_code == 9 && opt_len >= 1 && opt_off < body.len() {
                            let resol_byte = body[opt_off];
                            if resol_byte & 0x80 == 0 {
                                ts_resol = 10f64.powi(resol_byte as i32);
                            } else {
                                ts_resol = 2f64.powi((resol_byte & 0x7f) as i32);
                            }
                        }
                        opt_off += (opt_len + 3) & !3;
                    }
                }
            }
            PCAPNG_EPB => {
                if body.len() < 20 {
                    continue;
                }
                let ts_high = read_u32(&body[4..8], big_endian) as u64;
                let ts_low = read_u32(&body[8..12], big_endian) as u64;
                let captured_len = read_u32(&body[12..16], big_endian) as usize;
                let ts_raw = (ts_high << 32) | ts_low;
                let timestamp = ts_raw as f64 / ts_resol;
                let data_start = 20;
                let data_end = data_start + captured_len.min(body.len() - data_start);
                let pkt_data = &body[data_start..data_end];

                stats.total_packets += 1;

                let record = if link_type == 113 {
                    parse_sll_packet(pkt_data, timestamp)
                } else if link_type == 1 {
                    parse_packet(pkt_data, timestamp)
                } else {
                    None
                };
                if let Some(record) = record {
                    update_stats(&record, &mut stats);
                    handler(record);
                }
            }
            PCAPNG_SHB => {}
            _ => {}
        }
    }

    Ok(stats)
}

fn update_stats(record: &DnsRecord, stats: &mut ParseStats) {
    stats.dns_records += 1;
    if record.is_response {
        stats.responses += 1;
    }
    if record.query_type == 16 {
        stats.txt_records += 1;
    }
}

pub fn parse_packet(data: &[u8], timestamp: f64) -> Option<DnsRecord> {
    if data.len() < ETH_HEADER_LEN {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0800 {
        return None;
    }
    parse_ipv4_dns(&data[ETH_HEADER_LEN..], timestamp)
}

/// Parse a Linux cooked capture (SLL, link type 113) packet.
/// SLL header: 2 pkt_type + 2 ARPHRD + 2 addr_len + 8 addr + 2 protocol = 16 bytes
pub fn parse_sll_packet(data: &[u8], timestamp: f64) -> Option<DnsRecord> {
    if data.len() < SLL_HEADER_LEN {
        return None;
    }
    let protocol = u16::from_be_bytes([data[14], data[15]]);
    if protocol != 0x0800 {
        return None;
    }
    parse_ipv4_dns(&data[SLL_HEADER_LEN..], timestamp)
}

pub fn parse_ipv4_dns(data: &[u8], timestamp: f64) -> Option<DnsRecord> {
    if data.len() < 20 {
        return None;
    }
    let version = (data[0] >> 4) & 0x0F;
    if version != 4 {
        return None;
    }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    let protocol = data[9];
    if protocol != 17 {
        return None;
    }

    let src_ip = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    let dst_ip = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);

    let udp_data = &data[ihl..];
    if udp_data.len() < UDP_HEADER_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([udp_data[0], udp_data[1]]);
    let dst_port = u16::from_be_bytes([udp_data[2], udp_data[3]]);
    if src_port != 53 && dst_port != 53 {
        return None;
    }

    let dns_data = &udp_data[UDP_HEADER_LEN..];
    parse_dns(dns_data, timestamp, src_ip, src_port, dst_ip, dst_port)
}

fn parse_dns(
    data: &[u8],
    timestamp: f64,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
) -> Option<DnsRecord> {
    if data.len() < DNS_HEADER_LEN {
        return None;
    }

    let trans_id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = (flags >> 15) & 1 == 1;
    let rcode = (flags & 0x000F) as u8;
    let qd_count = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an_count = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut offset = DNS_HEADER_LEN;
    let mut query_name = String::new();
    let mut query_type = 0u16;

    for i in 0..qd_count {
        let (name, new_offset) = read_dns_name(data, offset)?;
        offset = new_offset;
        if offset + 4 > data.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 4;
        if i == 0 {
            query_name = name;
            query_type = qtype;
        }
    }

    let mut answers = Vec::new();
    for _ in 0..an_count {
        let (_name, new_offset) = match read_dns_name(data, offset) {
            Some(v) => v,
            None => break,
        };
        offset = new_offset;
        if offset + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlength > data.len() {
            break;
        }

        let rdata_bytes = &data[offset..offset + rdlength];
        let rdata = decode_rdata(rtype, rdata_bytes, data);

        answers.push(DnsAnswer {
            rtype,
            rtype_name: dns::qtype_to_name(rtype).to_string(),
            rdata,
            ttl,
        });
        offset += rdlength;
    }

    Some(DnsRecord {
        timestamp,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        proto: "udp".to_string(),
        trans_id,
        query_name,
        query_type,
        query_type_name: dns::qtype_to_name(query_type).to_string(),
        rcode,
        rcode_name: dns::rcode_to_name(rcode).to_string(),
        is_response,
        answers,
    })
}

fn read_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut return_offset = 0;
    let mut depth = 0;

    loop {
        if offset >= data.len() || depth > 64 {
            return None;
        }
        depth += 1;
        let len_byte = data[offset];

        if len_byte == 0 {
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }

        if (len_byte & 0xC0) == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            let pointer = ((len_byte as usize & 0x3F) << 8) | data[offset + 1] as usize;
            if !jumped {
                return_offset = offset + 2;
            }
            jumped = true;
            offset = pointer;
        } else {
            let label_len = len_byte as usize;
            offset += 1;
            if offset + label_len > data.len() {
                return None;
            }
            labels.push(String::from_utf8_lossy(&data[offset..offset + label_len]).to_string());
            offset += label_len;
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Some((name, return_offset))
}

fn decode_rdata(rtype: u16, rdata: &[u8], full_packet: &[u8]) -> String {
    match rtype {
        1 => {
            if rdata.len() == 4 {
                format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3])
            } else {
                hex_encode(rdata)
            }
        }
        28 => {
            if rdata.len() == 16 {
                (0..8)
                    .map(|i| format!("{:x}", u16::from_be_bytes([rdata[i * 2], rdata[i * 2 + 1]])))
                    .collect::<Vec<_>>()
                    .join(":")
            } else {
                hex_encode(rdata)
            }
        }
        2 | 5 | 12 => {
            let off = offset_in_packet(rdata, full_packet);
            if let Some((name, _)) = read_dns_name(full_packet, off) {
                name
            } else {
                hex_encode(rdata)
            }
        }
        15 => {
            if rdata.len() >= 2 {
                let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
                let name_off = offset_in_packet(rdata, full_packet) + 2;
                if let Some((name, _)) = read_dns_name(full_packet, name_off) {
                    format!("{} {}", pref, name)
                } else {
                    hex_encode(rdata)
                }
            } else {
                hex_encode(rdata)
            }
        }
        16 => decode_txt_rdata(rdata),
        _ => hex_encode(rdata),
    }
}

fn decode_txt_rdata(rdata: &[u8]) -> String {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < rdata.len() {
        let str_len = rdata[offset] as usize;
        offset += 1;
        if offset + str_len > rdata.len() {
            break;
        }
        result.extend_from_slice(&rdata[offset..offset + str_len]);
        offset += str_len;
    }
    String::from_utf8(result.clone())
        .unwrap_or_else(|_| String::from_utf8_lossy(&result).to_string())
}

fn offset_in_packet(slice: &[u8], packet: &[u8]) -> usize {
    let s = slice.as_ptr() as usize;
    let p = packet.as_ptr() as usize;
    s.saturating_sub(p)
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_txt_rdata() {
        assert_eq!(decode_txt_rdata(b"\x05hello"), "hello");
        assert_eq!(decode_txt_rdata(b"\x05hello\x06 world"), "hello world");
        assert_eq!(decode_txt_rdata(b""), "");
    }

    #[test]
    fn test_dns_name_simple() {
        let data = b"\x07example\x03com\x00";
        let (name, offset) = read_dns_name(data, 0).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(offset, 13);
    }

    #[test]
    fn test_dns_name_compressed() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x07example\x03com\x00");
        data.extend_from_slice(&[0xC0, 0x00]);
        let (name, offset) = read_dns_name(&data, 13).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(offset, 15);
    }
}
