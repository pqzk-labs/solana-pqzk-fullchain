---
title: 'solana-pqzk-fullchain: Full on-chain verification of ZK-STARK proofs and post-quantum signatures on Solana'
tags:
  - Solana
  - zero-knowledge proofs
  - STARK
  - post-quantum cryptography
  - "SLH-DSA (SPHINCS+)"
  - "ML-KEM (Kyber)"
authors:
  - name: Jotaro Yano
    orcid: 0009-0003-5327-9455
    corresponding: true
    affiliation: 1
affiliations:
  - name: Independent Researcher, Japan
    index: 1
date: 8 December 2025
bibliography: paper.bib
---

# Summary

`solana-pqzk-fullchain` is an open-source, research-oriented reference implementation that demonstrates **fully on-chain verification** of (i) a **hash-based zero-knowledge proof** (a STARK) and (ii) a **post-quantum digital signature** (SLH-DSA / SPHINCS+) on **Solana L1** [@pqzkFullchain]. The repository contains an on-chain verifier program (Anchor/SBF), a minimal off-chain STARK prover (Winterfell), a TypeScript CLI demo that runs an end-to-end flow (encrypt → prove → sign → upload → finalize → verify → receive), and benchmarking utilities that record transaction-level compute units (CUs) for each verification phase.

# Statement of need

Public blockchains preserve artifacts indefinitely, which creates a “record now, break later” risk profile for protocols whose security relies on assumptions that may be weakened by future capabilities, including Shor-type quantum attacks on discrete-log based systems [@Shor1999]. In practice, many deployed succinct proof systems use pairing-based SNARKs (e.g., Groth16, PLONK) because of small proofs and fast verification [@Groth16; @PLONK]. In contrast, STARKs are transparent (no trusted setup) and primarily hash-based, making them attractive when long-term post-quantum orientation is a design goal [@STARKePrint2018; @FRI]. The trade-off is that STARK verification is typically hashing-heavy and proof sizes are larger, so engineering feasibility depends strongly on the target execution environment.

Solana is a useful platform for studying this feasibility because it exposes explicit transaction compute accounting and strict runtime constraints (compute-unit limits, bounded stack, explicit heap-frame requests, and transaction/instruction size limits) that directly shape what can be verified on L1 [@SolanaFees; @SolanaComputeBudget; @SolanaTxSizeLimit]. However, implementing a full verifier pipeline on Solana L1 is non-trivial: hashing costs dominate, stack pressure can trigger SBF failures, memory allocation must be controlled, and large inputs require DoS- and fee-aware streaming.

`solana-pqzk-fullchain` addresses this gap by providing a complete, reproducible software stack focused on **engineering practicality** rather than proposing a new proof system:

- **CPI-friendly on-chain verifier surface:** a Solana program that verifies an **SLH-DSA (FIPS 205) signature** and a **Winterfell STARK proof** in separate phases to enable early rejection of malformed or unauthorized payloads [@FIPS205; @winterfell; @pqzkFullchain].
- **Binding of proofs to application artifacts:** the verifier derives public inputs from `SHA256(ciphertext)` and verifies a minimal AIR (affine counter) as a baseline mechanism for binding a proof to the uploaded ciphertext [@pqzkFullchain].
- **DoS- and fee-aware streaming uploads:** payloads are uploaded in bounded chunks with fixed-offset appends and a rolling SHA-256 hash chain, so invalid uploads can be rejected with constant work per chunk [@pqzkFullchain].
- **Runtime-aware adaptations for Solana SBF:** patched components route SHA-256 hashing through Solana’s `hashv` syscall, suppress inlining in FRI hotspots to respect stack limits, and use a bump allocator synchronized to the requested heap frame for predictable memory behavior [@pqzkFullchain].
- **End-to-end demo and benchmarking:** the repository includes a demo encryption path using a Kyber768/ML-KEM-style KEM for deriving an AEAD key (HKDF-SHA256) and AES-256-GCM encryption, plus scripts that repeatedly run the pipeline and log per-transaction compute units for the verification phases [@FIPS203; @pqzkFullchain].

This package is intended for researchers and engineers who need a reproducible baseline to (a) evaluate the feasibility and cost of PQ-oriented verification on Solana L1, (b) experiment with engineering levers (hashing path, stack discipline, heap sizing, streaming I/O), and (c) integrate a verifier via CPI into other Solana programs.

A longer methods-and-measurement report describing the same artifacts is available as a preprint on Zenodo and IACR ePrint; the JOSS paper intentionally focuses on the software contribution, interfaces, and reproducibility rather than new scientific findings [@YanoZenodo2025; @YanoEprint2025].

# Acknowledgements

This project builds on the Winterfell STARK ecosystem [@winterfell] and references the NIST post-quantum standards for ML-KEM and SLH-DSA [@FIPS203; @FIPS205]. It also relies on Solana’s public documentation for compute budgeting and transaction constraints [@SolanaFees; @SolanaComputeBudget; @SolanaTxSizeLimit]. No specific financial support was received for this work. The author declares no conflicts of interest.

# References
