//! BIP39 mnemonic <-> entropy, BIP32 derivation, and ETH/BTC address derivation.

use crate::crypto;
use secp256k1::Secp256k1;

/// Derive a BIP39 mnemonic string from raw entropy bytes.
pub fn mnemonic_from_entropy(entropy: &[u8]) -> String {
    bip39::Mnemonic::from_entropy(entropy).unwrap().to_string()
}

/// BIP39 seed (PBKDF2-HMAC-SHA512, 500 iterations, empty passphrase).
pub fn seed_from_entropy(entropy: &[u8]) -> Vec<u8> {
    bip39::Mnemonic::from_entropy(entropy).unwrap().to_seed("").to_vec()
}

/// Private key bytes at a BIP32 path.
fn privkey_at(seed: &[u8], path: &str) -> [u8; 32] {
    let secp = Secp256k1::new();
    let master = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Bitcoin, &seed).unwrap();
    let p: bitcoin::bip32::DerivationPath = path.parse().unwrap();
    let child = master.derive_priv(&secp, &p).unwrap();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&child.private_key.secret_bytes()[..]);
    pk
}

/// Ethereum address (last 20 bytes of Keccak-256 of the uncompressed public key).
pub fn eth_address_from_priv(pk: &[u8; 32]) -> String {
    let secp = Secp256k1::new();
    let secret = secp256k1::SecretKey::from_slice(pk).unwrap();
    let pub_un = secp256k1::PublicKey::from_secret_key(&secp, &secret).serialize_uncompressed();
    let h = crypto::keccak256(&pub_un[1..]);
    format!("0x{}", hex::encode(&h[12..]))
}

/// Bitcoin P2PKH (1...) address from a private key, using the compressed public key.
pub fn btc_address_from_priv(pk: &[u8; 32]) -> String {
    let secp = Secp256k1::new();
    let secret = secp256k1::SecretKey::from_slice(pk).unwrap();
    let pub_comp = secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let btc_pub = bitcoin::PublicKey::new(pub_comp);
    bitcoin::Address::p2pkh(&btc_pub, bitcoin::NetworkKind::Main).to_string()
}

/// All default derivation paths to test for a candidate.
pub fn default_paths() -> Vec<String> {
    vec![
        "m/44'/60'/0/0".to_string(), // ETH
        "m/44'/0'/0/0".to_string(),   // BTC legacy
        "m/84'/0'/0/0".to_string(),    // BTC bech32
        "m/0'/0'/0/0".to_string(),     // legacy
    ]
}

/// A full candidate wallet: mnemonic, entropy, and every derived address.
pub struct Wallet {
    pub mnemonic: String,
    pub entropy_hex: String,
    pub eth: Vec<String>,
    pub btc: Vec<String>,
}

/// Derive every address for a candidate entropy value.
pub fn derive_wallet(entropy: &[u8]) -> Wallet {
    let mnemonic = mnemonic_from_entropy(entropy);
    let seed = seed_from_entropy(entropy);
    let mut eth = Vec::new();
    let mut btc = Vec::new();
    for path in default_paths() {
        let pk = privkey_at(&seed, &path);
        let e = eth_address_from_priv(&pk);
        let b = btc_address_from_priv(&pk);
        if !eth.contains(&e) {
            eth.push(e);
        }
        if !btc.contains(&b) {
            btc.push(b);
        }
    }
    Wallet {
        mnemonic,
        entropy_hex: hex::encode(entropy),
        eth,
        btc,
    }
}
