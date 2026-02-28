//! Plumbum MCP Server — stdio JSON-RPC transport.
//!
//! Exposes read-only analysis results as MCP resources and tools.

use std::io::{self, BufRead, Write};

mod protocol;

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        let response = protocol::handle_request(&line);
        let _ = writeln!(stdout, "{}", response);
        let _ = stdout.flush();
    }
}
