//! Live network capture and real-time DNS anomaly scoring.
//!
//! Captures DNS traffic from a network interface via libpcap,
//! accumulates records per domain in a sliding time window,
//! and scores them through the plumbum-score pipeline.

pub mod accumulator;
pub mod capture;
pub mod scorer;
