//! WASM bindings for SLH DSA SHA2 128s
//! Exposes key generation signing and verification for JavaScript

#![allow(clippy::missing_safety_doc)]

use wasm_bindgen::prelude::*;
use serde::Serialize;
use slh_dsa::{
    Sha2_128s, SigningKey, VerifyingKey, Signature,
    signature::{Keypair, Signer, Verifier},
};
use rand_core::OsRng;
use core::convert::TryFrom;

const SK_LEN : usize = 64; // Defines private key length in bytes
const PK_LEN : usize = 32; // Defines public key length in bytes
const SIG_LEN: usize = 7_856; // Defines signature length in bytes

#[derive(Serialize)]
struct KeyPair { public_key: Vec<u8>, private_key: Vec<u8> }

/// Generates a new keypair and returns a JSON value
#[wasm_bindgen]
pub fn generate_keypair() -> JsValue {
    let sk = SigningKey::<Sha2_128s>::new(&mut OsRng);
    let pk = sk.verifying_key();
    serde_wasm_bindgen::to_value(&KeyPair {
        public_key : pk.to_bytes().to_vec(),
        private_key: sk.to_bytes().to_vec(),
    }).unwrap()
}

/// Derives verifying key bytes from a signing key
#[wasm_bindgen]
pub fn vk_bytes_from_sk(sk_bytes: &[u8]) -> Vec<u8> {
    if sk_bytes.len() != SK_LEN { return vec![]; }
    let sk = SigningKey::<Sha2_128s>::try_from(sk_bytes).unwrap();
    sk.verifying_key().to_bytes().to_vec()
}

/// Signs the message with SLH DSA SHA2 128s
#[wasm_bindgen]
pub fn sign(msg: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    if sk_bytes.len() != SK_LEN {
        return Err(JsValue::from_str("invalid_sk_length"));
    }
    let sk = SigningKey::<Sha2_128s>::try_from(sk_bytes)
        .map_err(|_| JsValue::from_str("decode_sk"))?;
    let sig: Signature<Sha2_128s> = sk.sign(msg);
    Ok(sig.to_bytes().to_vec())
}

/// Verifies the signature with the given verifying key
#[wasm_bindgen]
pub fn verify(msg: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> bool {
    if pk_bytes.len() != PK_LEN || sig_bytes.len() != SIG_LEN { return false; }
    let pk  = match VerifyingKey::<Sha2_128s>::try_from(pk_bytes) { Ok(v)=>v, Err(_)=>return false };
    let sig = match Signature::<Sha2_128s>::try_from(sig_bytes)   { Ok(s)=>s, Err(_)=>return false };
    pk.verify(msg, &sig).is_ok()
}
