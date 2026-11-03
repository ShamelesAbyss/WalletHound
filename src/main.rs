mod cli;
mod check;
mod bip39;
mod crypto;
mod entropy;
mod recorder;
mod stats;

use crate::cli::{Args, Mode};
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        cli::print_help();
        return;
    }
    let a = cli::parse(&args);
    match a.mode {
        Mode::Recover => recover(&a),
        Mode::Test => test(&a),
        Mode::Offline => offline(&a),
        Mode::Feasibility => feasibility(&a),
        Mode::Bench => bench(&a),
    }
}

/// Build candidates from explicit entropy inputs (the legitimate recovery path).
/// Returns an empty Vec if no entropy input was provided.
fn entropy_candidates(a: &Args) -> Vec<entropy::Candidate> {
    if !a.entropy_hex.is_empty() {
        let bytes = hex::decode(&a.entropy_hex).unwrap_or_else(|_| {
            println!("error: --entropy-hex is not valid hex: {}", a.entropy_hex);
            std::process::exit(1);
        });
        if !crypto::valid_entropy_len(bytes.len()) {
            println!(
                "error: entropy must be 11/12/16/20/24/28/32 bytes (got {} bytes)",
                bytes.len()
            );
            std::process::exit(1);
        }
        return vec![entropy::Candidate::new("explicit", bytes)];
    }
    if !a.entropy_file.is_empty() {
        let content = std::fs::read_to_string(&a.entropy_file).unwrap_or_else(|e| {
            println!("error: cannot read {}: {}", a.entropy_file, e);
            std::process::exit(1);
        });
        let mut v = Vec::new();
        let mut n = 0;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let bytes = hex::decode(line).unwrap_or_else(|_| {
                println!("error: line {} is not valid hex: {}", n, line);
                std::process::exit(1);
            });
            if !crypto::valid_entropy_len(bytes.len()) {
                println!("error: line {} has invalid entropy length {} bytes", n, bytes.len());
                std::process::exit(1);
            }
            v.push(entropy::Candidate::new("file", bytes));
            n += 1;
        }
        v
    } else {
        Vec::new()
    }
}

/// Build candidates from entropy inputs, falling back to strategy enumeration.
fn build_candidates(a: &Args) -> Vec<entropy::Candidate> {
    let c = entropy_candidates(a);
    if !c.is_empty() {
        return c;
    }
    entropy::enumerate(&a.strategy, a.count)
}

/// Recover: derive known entropy values + check balances + record hits.
fn recover(a: &Args) {
    let cands = entropy_candidates(a);
    if cands.is_empty() {
        println!("recover mode requires entropy input.");
        println!("  --entropy-hex HEX      (a single entropy value)");
        println!("  --entropy-file FILE    (a file of hex entropy values, one per line)");
        println!();
        println!("This is the only legitimate recovery path. It derives the wallet for entropy");
        println!("you know, checks balances, and logs any funded wallet.");
        std::process::exit(1);
    }
    process(&a, cands, "recover");
}

/// Test: enumerate a deterministic generator + derive + check (pipeline verification ONLY).
fn test(a: &Args) {
    println!("NOTE: test mode enumerates deterministic patterns for PIPELINE VERIFICATION ONLY.");
    println!("It does NOT find funded wallets. See README: 'Why structured search does not hunt'.");
    println!();
    let cands = entropy::enumerate(&a.strategy, a.count);
    if cands.is_empty() {
        println!("Unknown strategy: {}", a.strategy);
        std::process::exit(1);
    }
    process(&a, cands, "test");
}

/// Offline: derive only (no network). Writes candidate wallets to a file.
fn offline(a: &Args) {
    let cands = build_candidates(&a);
    if cands.is_empty() {
        println!("offline mode needs entropy input or --strategy.");
        std::process::exit(1);
    }
    let wallets = derive_parallel(&cands);
    let mut n_addrs = 0;
    for (_, w) in &wallets {
        n_addrs += w.eth.len() + w.btc.len();
    }
    let mut file = std::fs::File::create(&a.out_file).unwrap();
    for (gen, w) in &wallets {
        let line = format!(
            "{} | {} | ETH: {} | BTC: {}\n",
            gen,
            w.mnemonic,
            w.eth.join(", "),
            w.btc.join(", ")
        );
        let _ = file.write_all(line.as_bytes());
    }
    println!(
        "offline: derived {} wallets / {} addresses -> {} (no network).",
        wallets.len(),
        n_addrs,
        a.out_file
    );
    // Show the first wallet in full so the derivation can be eyeballed.
    if let Some((gen, w)) = wallets.first() {
        println!("--- sample (first candidate) ---");
        println!("generator: {}", gen);
        println!("mnemonic:  {}", w.mnemonic);
        println!("ETH: {}", w.eth.join(", "));
        println!("BTC: {}", w.btc.join(", "));
    }
}

/// Feasibility: print the cost of enumerating a strategy (not a recovery yield).
fn feasibility(a: &Args) {
    let total = entropy::total(&a.strategy);
    let n = a.count;
    let per_candidate_checks: u64 = if a.eth { 1 } else { 0 } + if a.btc { 1 } else { 0 };
    let f = stats::feasibility(n, per_candidate_checks, 100);
    println!("Strategy: {}", a.strategy);
    println!("Candidates: {}", n);
    let total_str = if total == u64::max_value() {
        "unbounded".to_string()
    } else {
        total.to_string()
    };
    println!("Total strategy space: {}", total_str);
    println!("Checks per candidate: {}", per_candidate_checks);
    println!("Total network checks: {}", f.total_checks);
    println!(
        "Estimated enumeration time @100 checks/s: {}",
        stats::fmt_duration(f.seconds)
    );
    println!();
    println!("NOTE: this is the cost of ENUMERATING candidates, not a recovery yield.");
    println!("The chance that any enumerated address holds funds is negligible.");
    println!("Deterministic enumeration is only legitimate for reproducing a SPECIFIC");
    println!("documented bug — use --recover with the exact entropy value.");
}

/// Benchmark local derivation throughput.
fn bench(a: &Args) {
    let n = a.count;
    let cands = entropy::enumerate(&a.strategy, n);
    let t = std::time::Instant::now();
    let mut count = 0;
    for c in &cands {
        bip39::derive_wallet(&c.entropy);
        count += 1;
    }
    let dt = t.elapsed().as_secs_f64();
    let per_sec = count as f64 / dt;
    println!(
        "Bench {}: derived {} wallets in {:.3}s => {:.0} wallets/s",
        a.strategy,
        count,
        dt,
        per_sec
    );
}

/// Derive wallets in parallel across threads.
fn derive_parallel(cands: &[entropy::Candidate]) -> Vec<(String, bip39::Wallet)> {
    let nthreads = num_cpus::get().max(1);
    let chunk = (cands.len() / nthreads).max(1);
    let mut handles = Vec::new();
    for t in 0..nthreads {
        let start = (t * chunk).min(cands.len());
        let end = ((t + 1) * chunk).min(cands.len());
        let slice = cands[start..end].to_vec();
        handles.push(std::thread::spawn(move || {
            let mut v = Vec::new();
            for c in &slice {
                v.push((c.generator.clone(), bip39::derive_wallet(&c.entropy)));
            }
            v
        }));
    }
    let mut wallets: Vec<(String, bip39::Wallet)> = Vec::new();
    for h in handles {
        wallets.extend(h.join().unwrap());
    }
    wallets
}

/// Shared core: derive + batch-check balances + record hits.
fn process(a: &Args, cands: Vec<entropy::Candidate>, label: &str) {
    let wallets = derive_parallel(&cands);

    let mut addrs: Vec<String> = Vec::new();
    for (_, w) in &wallets {
        if a.eth {
            addrs.extend_from_slice(&w.eth);
        }
        if a.btc {
            addrs.extend_from_slice(&w.btc);
        }
    }
    println!(
        "{}: derived {} wallets -> {} addresses to check.",
        label,
        wallets.len(),
        addrs.len()
    );

    let mut checker = check::Checker::new(&a.api_key);
    let hits = checker.check_batch(&addrs);

    // Map every address back to its wallet index for hit attribution.
    let mut map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (i, (_, w)) in wallets.iter().enumerate() {
        for addr in w.eth.iter().chain(w.btc.iter()) {
            map.insert(addr.clone(), i);
        }
    }

    let mut found = 0;
    for (addr, bal) in &hits {
        if let Some(&i) = map.get(addr) {
            let (gen, w) = &wallets[i];
            recorder::record(
                &a.out_file,
                &recorder::Recovery {
                    generator: gen.clone(),
                    entropy_hex: w.entropy_hex.clone(),
                    mnemonic: w.mnemonic.clone(),
                    eth: w.eth.clone(),
                    btc: w.btc.clone(),
                    balance_addr: addr.clone(),
                    balance: *bal,
                },
            );
            found += 1;
        }
    }
    println!(
        "{} complete. Checked {} addresses, {} hits. Recoveries logged to {}.",
        label,
        checker.checked,
        found,
        a.out_file
    );
}
