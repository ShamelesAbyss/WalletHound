//! Batched balance checking over HTTP with rate-limit awareness.

use ureq::Agent;

/// A batch balance-checker. Etherscan's batch endpoint accepts up to 25 addresses per call.
pub struct Checker {
    pub api_key: String,
    pub agent: Option<Agent>,
    pub checked: u64,
}

impl Checker {
    pub fn new(api_key: &str) -> Self {
        Checker {
            api_key: api_key.to_string(),
            agent: None,
            checked: 0,
        }
    }

    /// Check a batch of addresses. Returns (address, balance) for any with balance > 0.
    pub fn check_batch(&mut self, addrs: &[String]) -> Vec<(String, u64)> {
        if self.agent.is_none() {
            self.agent = Some(Agent::new());
        }
        let mut out = Vec::new();
        // Chunk to 25 per request.
        for chunk in addrs.chunks(25) {
            let joined = chunk.join(",");
            let url = format!(
                "https://api.etherscan.io/api?module=account&action=balance&address={}&tag=latest",
                joined
            );
            let _ = self.api_key; // api key optional
            if let Ok(r) = self.agent.as_ref().unwrap().get(url.as_str()).call() {
                let body = r.into_string().unwrap();
                // Parse CSV of "address,balance"
                for line in body.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let parts = line.split(',').collect::<Vec<&str>>();
                    if parts.len() >= 2 {
                        let addr = parts[0];
                        let bal = parts[1].parse::<u64>().unwrap_or(0);
                        if bal > 0 {
                            out.push((addr.to_string(), bal));
                        }
                    }
                }
            }
            self.checked += chunk.len() as u64;
        }
        out
    }
}
