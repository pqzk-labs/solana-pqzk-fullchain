# Security Policy

⚠️ **Research code — not audited. Do not use in production.**

If you discover a vulnerability:
- Use GitHub’s **“Report a vulnerability”** (Security tab), or  
- Email: <jotaro.yano@jotaro-yano.org>

For non‑security bugs, feel free to open a public Issue.  
If you must file an Issue about a vuln, omit exploit details and we’ll move the discussion to a private channel.  
We aim to acknowledge within 3 business days.

Known limitations: not FIPS‑validated; STARK verifier targets ~128‑bit with a conservative cap (MinConjecturedSecurity(127)); basic DoS controls (chunked uploads, CU/heap tuning); signature buffer retained for readers; devnet/testnet only.
