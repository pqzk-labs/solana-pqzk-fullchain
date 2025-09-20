//! CLI wrapper that reads a hex SHA256 digest and writes proof.bin

use std::{env, fs};
use stark_prover::generate_proof;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 || args[1] != "gen" {
        eprintln!("usage: cargo run -p stark-prover --release -- gen <sha256_hex>");
        std::process::exit(1);
    }
    let hash_hex = &args[2];
    let hash_bytes = hex::decode(hash_hex)?;
    let (_params_bin, proof_bin) = generate_proof(&hash_bytes)?;
    fs::write("proof.bin", &proof_bin)?;
    println!("proof.bin generated ✅");
    Ok(())
}
