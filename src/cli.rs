//! Minimal hand-rolled CLI (no external arg crate).

#[derive(Clone, Copy)]
pub enum Mode {
    Recover,
    Test,
    Offline,
    Feasibility,
    Bench,
}

#[derive(Clone)]
pub struct Args {
    pub mode: Mode,
    pub strategy: String,
    pub count: u64,
    pub api_key: String,
    pub out_file: String,
    pub eth: bool,
    pub btc: bool,
    pub entropy_hex: String,
    pub entropy_file: String,
}

pub fn parse(args: &[String]) -> Args {
    let mut mode = Mode::Recover;
    let mut strategy = "counter".to_string();
    let mut count = 100000u64;
    let mut api_key = String::new();
    let mut out_file = "recovered_wallets.jsonl".to_string();
    let mut eth = true;
    let mut btc = true;
    let mut entropy_hex = String::new();
    let mut entropy_file = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--recover" => mode = Mode::Recover,
            "--test" => mode = Mode::Test,
            "--offline" => mode = Mode::Offline,
            "--feasibility" => mode = Mode::Feasibility,
            "--bench" => mode = Mode::Bench,
            "--strategy" => {
                i += 1;
                strategy = args[i].clone();
            }
            "--count" => {
                i += 1;
                count = args[i].parse().unwrap_or(100000);
            }
            "--api-key" => {
                i += 1;
                api_key = args[i].clone();
            }
            "--out" => {
                i += 1;
                out_file = args[i].clone();
            }
            "--eth" => eth = true,
            "--btc" => btc = true,
            "--entropy-hex" => {
                i += 1;
                entropy_hex = args[i].clone();
            }
            "--entropy-file" => {
                i += 1;
                entropy_file = args[i].clone();
            }
            _ => {}
        }
        i += 1;
    }
    Args {
        mode,
        strategy,
        count,
        api_key,
        out_file,
        eth,
        btc,
        entropy_hex,
        entropy_file,
    }
}

pub fn print_help() {
    println!("WalletHound — a wallet-recovery engine (ETH + BTC).");
    println!();
    println!("This tool recovers wallets from KNOWN entropy values. It derives the BIP39/BIP32");
    println!("wallet for a given entropy, checks balances over the network, and logs any funded");
    println!("wallet to a file. The only legitimate input is entropy you actually know or have a");
    println!("documented reason to reproduce. It does NOT hunt: enumerating entropy without a");
    println!("specific reason has negligible yield (address space ~2^160).");
    println!();
    println!("Usage: wallet-hound [mode] [options]");
    println!();
    println!("Modes:");
    println!("  --recover         Recover from known entropy (--entropy-hex / --entropy-file).");
    println!("  --test            Pipeline verification only: enumerate a generator, derive, check.");
    println!("                    NOT a fund finder. Use to prove the pipeline works.");
    println!("  --offline         Derive only (no network). Writes candidate wallets to a file.");
    println!("  --feasibility     Print the cost of enumerating a strategy (no network).");
    println!("  --bench           Benchmark local derivation throughput (no network).");
    println!();
    println!("Recovery input (recover mode — required):");
    println!("  --entropy-hex HEX   A single entropy value in hex (11/12/16/20/24/28/32 bytes).");
    println!("  --entropy-file F    A file of entropy values, one hex value per line.");
    println!();
    println!("Test-mode input (test/offline only):");
    println!("  --strategy NAME   zero | counter | counter_be | low_byte | repeated | ascii | year");
    println!("  --count N         Candidates to enumerate (default 100000).");
    println!();
    println!("Options:");
    println!("  --api-key KEY     Etherscan API key (optional, for rate-limiting).");
    println!("  --out FILE        Output file (default recovered_wallets.jsonl).");
    println!("  --eth / --btc     Toggle ETH / BTC checking (both on by default).");
}
