//! Logs recovered wallets (seed phrase + address + evidence) to disk.

use serde::Serialize;

#[derive(Serialize)]
pub struct Recovery {
    pub generator: String,
    pub entropy_hex: String,
    pub mnemonic: String,
    pub eth: Vec<String>,
    pub btc: Vec<String>,
    pub balance_addr: String,
    pub balance: u64,
}

/// Append a recovery record to a JSON-lines file and print it.
pub fn record(out_file: &str, r: &Recovery) {
    use std::io::Write;
    let line = serde_json::to_string(r).unwrap();
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(out_file)
    {
        writeln!(f, "{}", line).ok();
    }
    println!("FOUND {} @ {} (generator={}) balance={} ETH", r.balance_addr, r.mnemonic, r.generator, r.balance);
}
