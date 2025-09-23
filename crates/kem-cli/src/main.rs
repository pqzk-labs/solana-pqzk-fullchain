//! Kyber768 KEM CLI for the zk chat demo.
//! Prints one JSON object to stdout per command.
//! Keeps JSON field names pkB64 ctB64 ssB64 via serde rename.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Parser, Subcommand};
use serde::Serialize;

// Uses Kyber768 as the concrete KEM.
use pqcrypto_kyber::kyber768 as kem;
// Brings KEM traits for as_bytes and from_bytes.
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};

/// Defines the CLI and the selected subcommand.
#[derive(Parser, Debug)]
#[command(name = "kem-cli")]
#[command(about = "Kyber768 KEM helper (gen encap decap) for zk chat", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Lists available subcommands.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Generates a Kyber768 keypair and prints JSON.
    Gen,
    /// Encapsulates to a base64 public key and prints JSON.
    Encap {
        #[arg(long)]
        pk: String,
    },
    /// Decapsulates with a base64 secret key and ciphertext and prints JSON.
    Decap {
        #[arg(long)]
        sk: String,
        #[arg(long)]
        ct: String,
    },
}

/// Holds JSON output of gen.
#[derive(Serialize)]
struct OutGen {
    alg: &'static str,
    #[serde(rename = "pkB64")]
    pk_b64: String,
    #[serde(rename = "skB64")]
    sk_b64: String,
    pk_len: usize,
    sk_len: usize,
}

/// Holds JSON output of encap.
#[derive(Serialize)]
struct OutEncap {
    alg: &'static str,
    #[serde(rename = "ctB64")]
    ct_b64: String,
    #[serde(rename = "ssB64")]
    ss_b64: String,
    ct_len: usize,
    ss_len: usize,
}

/// Holds JSON output of decap.
#[derive(Serialize)]
struct OutDecap {
    alg: &'static str,
    #[serde(rename = "ssB64")]
    ss_b64: String,
    ss_len: usize,
}

fn main() -> Result<()> {
    // Parses flags and dispatches.
    let cli = Cli::parse();

    match cli.command {
        Commands::Gen => {
            let (pk, sk) = kem::keypair();
            let out = OutGen {
                alg: "kyber768",
                pk_b64: STANDARD.encode(pk.as_bytes()),
                sk_b64: STANDARD.encode(sk.as_bytes()),
                pk_len: kem::public_key_bytes(),
                sk_len: kem::secret_key_bytes(),
            };
            println!("{}", serde_json::to_string(&out)?);
        }
        Commands::Encap { pk } => {
            let pk_bytes = STANDARD.decode(pk)?;
            let pk = kem::PublicKey::from_bytes(&pk_bytes)
                .map_err(|_| anyhow!("invalid Kyber768 public key length"))?;
            let (ss, ct) = kem::encapsulate(&pk);
            let out = OutEncap {
                alg: "kyber768",
                ct_b64: STANDARD.encode(ct.as_bytes()),
                ss_b64: STANDARD.encode(ss.as_bytes()),
                ct_len: kem::ciphertext_bytes(),
                ss_len: kem::shared_secret_bytes(),
            };
            println!("{}", serde_json::to_string(&out)?);
        }
        Commands::Decap { sk, ct } => {
            let sk_bytes = STANDARD.decode(sk)?;
            let ct_bytes = STANDARD.decode(ct)?;
            let sk = kem::SecretKey::from_bytes(&sk_bytes)
                .map_err(|_| anyhow!("invalid Kyber768 secret key length"))?;
            let ct = kem::Ciphertext::from_bytes(&ct_bytes)
                .map_err(|_| anyhow!("invalid Kyber768 ciphertext length"))?;
            let ss = kem::decapsulate(&ct, &sk);
            let out = OutDecap {
                alg: "kyber768",
                ss_b64: STANDARD.encode(ss.as_bytes()),
                ss_len: kem::shared_secret_bytes(),
            };
            println!("{}", serde_json::to_string(&out)?);
        }
    }

    Ok(())
}
