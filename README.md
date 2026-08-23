        STM — Secure Transfer Manifest
--------------------------------------------

STM is a Rust-based secure container format for storing multiple objects with integrity verification and optional Ed25519 digital signatures.

Features
--------------
Binary STM container format
Fixed-size 72-byte header
Object directory
Canonical object ordering
Duplicate OID detection
SHA-based Merkle tree integrity verification
Ed25519 digital signatures
Public/private key generation
Signed and unsigned containers
Object tamper detection
Signature tamper detection
Command-line interface

Project Architecture
----------------------

STM
│
├── stm-core
│   └── Core types and errors
│
├── stm-binary
│   └── Header and signature block serialization
│
├── stm-container
│   └── Object directory management
│
├── stm-crypto
│   └── Merkle tree and hashing
│
├── stm-signature
│   └── Ed25519 signing and verification
│
├── stm-writer
│   └── STM container creation
│
├── stm-parser
│   └── STM container parsing and validation
│
└── stm-cli
    └── Command-line interface


Build
-----------
cargo fmt
cargo check --workspace
cargo test --workspace


Generate Keys
---------------
cargo run -p stm-cli -- keygen keys


This generates:

keys/
├── private.key
└── public.key

Create an Unsigned Container
-------------------------------
cargo run -p stm-cli -- create test.stmf --count 3

Create a Signed Container
--------------------------------
cargo run -p stm-cli -- create signed.stmf --count 3 --signed --key keys\private.key

Verify a Container
------------------------------
cargo run -p stm-cli -- verify signed.stmf

Expected result:

Merkle Integrity: VALID
Signed: YES
Digital Signature: VALID
Result: VALID


Security Verification
-----------------------
STM detects modifications to object data using the Merkle root.

Example:

Result: INVALID
Reason: Merkle root mismatch

STM also detects modifications to the digital signature.

Example:

Digital Signature: INVALID
Result: INVALID
Reason: Digital signature verification failed

Testing
------------------
Run all workspace tests:
cargo test --workspace

Current tests include:
--------------------
Header serialization
Header validation
Directory validation
Directory ordering
Object bounds checking
Merkle tree generation
Merkle root validation
Writer/parser round trips
Duplicate OID detection
Object tampering detection
Signed container tampering detection
Signature tampering detection
Ed25519 signature verification