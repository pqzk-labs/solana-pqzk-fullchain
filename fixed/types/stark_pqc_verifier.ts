/**
 * Program IDL in camelCase format in order to be used in JS/TS.
 *
 * Note that this is only a type helper and is not the actual IDL. The original
 * IDL can be found at `target/idl/stark_pqc_verifier.json`.
 */
export type StarkPqcVerifier = {
  "address": "CECNRbDxFQVfWiQwvG8qcSGPGSk8eLWraBCERcdL5DKT",
  "metadata": {
    "name": "starkPqcVerifier",
    "version": "0.1.0",
    "spec": "0.1.0"
  },
  "instructions": [
    {
      "name": "finalizeSig",
      "docs": [
        "Step 1: Verifies SLH-DSA and persists a ChatMsg."
      ],
      "discriminator": [
        242,
        146,
        145,
        38,
        7,
        139,
        219,
        156
      ],
      "accounts": [
        {
          "name": "buffer",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  98,
                  117,
                  102
                ]
              },
              {
                "kind": "account",
                "path": "payer"
              }
            ]
          }
        },
        {
          "name": "sigbuf",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  115,
                  105,
                  103
                ]
              },
              {
                "kind": "account",
                "path": "payer"
              },
              {
                "kind": "account",
                "path": "recipient"
              },
              {
                "kind": "arg",
                "path": "slot"
              }
            ]
          }
        },
        {
          "name": "chatMsg",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  109,
                  115,
                  103
                ]
              },
              {
                "kind": "account",
                "path": "payer"
              },
              {
                "kind": "account",
                "path": "recipient"
              },
              {
                "kind": "arg",
                "path": "slot"
              }
            ]
          }
        },
        {
          "name": "recipient"
        },
        {
          "name": "payer",
          "writable": true,
          "signer": true
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "cipherLen",
          "type": "u32"
        },
        {
          "name": "kemLen",
          "type": "u32"
        },
        {
          "name": "nonce",
          "type": {
            "array": [
              "u8",
              12
            ]
          }
        },
        {
          "name": "slot",
          "type": "u64"
        },
        {
          "name": "slhPub",
          "type": {
            "array": [
              "u8",
              32
            ]
          }
        }
      ]
    },
    {
      "name": "initBuffer",
      "docs": [
        "Initializes the body buffer PDA used for streaming uploads, zeros length and sha_chain."
      ],
      "discriminator": [
        123,
        211,
        233,
        210,
        166,
        139,
        218,
        60
      ],
      "accounts": [
        {
          "name": "buffer",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  98,
                  117,
                  102
                ]
              },
              {
                "kind": "account",
                "path": "payer"
              }
            ]
          }
        },
        {
          "name": "payer",
          "writable": true,
          "signer": true
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": []
    },
    {
      "name": "initSignature",
      "docs": [
        "Initializes the signature buffer PDA for a (sender, recipient, slot) tuple."
      ],
      "discriminator": [
        92,
        231,
        134,
        178,
        185,
        71,
        16,
        65
      ],
      "accounts": [
        {
          "name": "buffer",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  115,
                  105,
                  103
                ]
              },
              {
                "kind": "account",
                "path": "payer"
              },
              {
                "kind": "arg",
                "path": "recipient"
              },
              {
                "kind": "arg",
                "path": "slot"
              }
            ]
          }
        },
        {
          "name": "recipient"
        },
        {
          "name": "payer",
          "writable": true,
          "signer": true
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "recipient",
          "type": "pubkey"
        },
        {
          "name": "slot",
          "type": "u64"
        }
      ]
    },
    {
      "name": "uploadBody",
      "docs": [
        "Appends a body chunk to the body buffer (cipher || kem || proof) with hash-chaining."
      ],
      "discriminator": [
        66,
        112,
        164,
        113,
        136,
        164,
        71,
        93
      ],
      "accounts": [
        {
          "name": "buffer",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  98,
                  117,
                  102
                ]
              },
              {
                "kind": "account",
                "path": "sender"
              }
            ]
          }
        },
        {
          "name": "sender",
          "signer": true
        }
      ],
      "args": [
        {
          "name": "off",
          "type": "u32"
        },
        {
          "name": "data",
          "type": "bytes"
        },
        {
          "name": "hash",
          "type": {
            "array": [
              "u8",
              32
            ]
          }
        }
      ]
    },
    {
      "name": "uploadSignature",
      "docs": [
        "Appends a signature chunk to the signature buffer with hash-chaining."
      ],
      "discriminator": [
        70,
        173,
        39,
        245,
        227,
        47,
        161,
        131
      ],
      "accounts": [
        {
          "name": "buffer",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  115,
                  105,
                  103
                ]
              },
              {
                "kind": "account",
                "path": "sender"
              },
              {
                "kind": "arg",
                "path": "recipient"
              },
              {
                "kind": "arg",
                "path": "slot"
              }
            ]
          }
        },
        {
          "name": "sender",
          "signer": true
        },
        {
          "name": "recipient"
        },
        {
          "name": "chatMsg",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  109,
                  115,
                  103
                ]
              },
              {
                "kind": "account",
                "path": "sender"
              },
              {
                "kind": "arg",
                "path": "recipient"
              },
              {
                "kind": "arg",
                "path": "slot"
              }
            ]
          }
        }
      ],
      "args": [
        {
          "name": "recipient",
          "type": "pubkey"
        },
        {
          "name": "slot",
          "type": "u64"
        },
        {
          "name": "off",
          "type": "u32"
        },
        {
          "name": "data",
          "type": "bytes"
        },
        {
          "name": "hash",
          "type": {
            "array": [
              "u8",
              32
            ]
          }
        }
      ]
    },
    {
      "name": "verifyStark",
      "docs": [
        "Step 2: Verifies the STARK proof for the affine-counter AIR."
      ],
      "discriminator": [
        31,
        145,
        209,
        185,
        124,
        219,
        77,
        211
      ],
      "accounts": [
        {
          "name": "chatMsg"
        }
      ],
      "args": []
    }
  ],
  "accounts": [
    {
      "name": "bufferPda",
      "discriminator": [
        168,
        232,
        123,
        66,
        15,
        173,
        224,
        25
      ]
    },
    {
      "name": "chatMsg",
      "discriminator": [
        88,
        253,
        180,
        118,
        244,
        42,
        109,
        102
      ]
    }
  ],
  "errors": [
    {
      "code": 6000,
      "name": "chunkTooLarge",
      "msg": "chunk > 900 bytes"
    },
    {
      "code": 6001,
      "name": "offsetMismatch",
      "msg": "offset mismatch"
    },
    {
      "code": 6002,
      "name": "msgTooBig",
      "msg": "buffer overflow"
    },
    {
      "code": 6003,
      "name": "hashMismatch",
      "msg": "hash mismatch"
    },
    {
      "code": 6004,
      "name": "alreadyFinalized",
      "msg": "signature buffer is frozen (finalized)"
    }
  ],
  "types": [
    {
      "name": "bufferPda",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "sender",
            "type": "pubkey"
          },
          {
            "name": "length",
            "type": "u32"
          },
          {
            "name": "shaChain",
            "type": {
              "array": [
                "u8",
                32
              ]
            }
          }
        ]
      }
    },
    {
      "name": "chatMsg",
      "docs": [
        "Finalized chat message: payload = cipher || kem || proof (STARK proof)."
      ],
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "sender",
            "type": "pubkey"
          },
          {
            "name": "recipient",
            "type": "pubkey"
          },
          {
            "name": "cipherLen",
            "type": "u32"
          },
          {
            "name": "kemLen",
            "type": "u32"
          },
          {
            "name": "nonce",
            "type": {
              "array": [
                "u8",
                12
              ]
            }
          },
          {
            "name": "slot",
            "type": "u64"
          },
          {
            "name": "sigPda",
            "type": "pubkey"
          },
          {
            "name": "sigLen",
            "type": "u32"
          },
          {
            "name": "sigHash",
            "type": {
              "array": [
                "u8",
                32
              ]
            }
          },
          {
            "name": "payload",
            "type": "bytes"
          }
        ]
      }
    }
  ]
};
