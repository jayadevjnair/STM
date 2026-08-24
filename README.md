# STM — Secure / Structured Trusted Media Container

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/Integrity-Merkle%20Tree%20%2B%20Ed25519-blueviolet)]()

**STM (`.stmf`)** is a high-performance, tamper-evident binary media and file container written in Rust. It encapsulates arbitrary digital media (PNG, JPEG, PDF, MP4, MP3, ZIP, TXT) alongside cryptographically bound metadata, enforcing **Merkle-tree data integrity** and **Ed25519 digital signatures**.

If even a single bit of a container's content, metadata, or signature is altered, the STM parser detects the tampering, rejects the container as **INVALID**, and prevents unauthorized extraction or rendering.

---

## 🚀 What's New in v1.1.0

* **Streaming File Conversion**: Two-pass chunked stream writer (`convert_file_to_stmf_streaming`) for large files without loading entire files into RAM.
* **Streaming Verification & Extraction**: Incremental container hashing and extraction (`verify_file_streaming`, `extract_file_streaming`) with bounded 4 MiB buffers.
* **New `stm-stream` Crate**: Modular chunk readers, writers, and `ProgressReporter` traits.
* **CLI Progress Bars**: Real-time terminal progress indicators for `file-create`, `verify`, and `extract`.
* **Web UI Progress Reporting**: Live progress bars for file conversion and verification.
* **100% Backward Compatible**: Retains identical 72-byte binary header and object Merkle root format.

---

## 🌟 Key Features

* **Fixed 72-Byte Binary Header**: Compact, constant-size binary container header storing magic identifier, version, total container length, and SHA-256 Merkle root.
* **Merkle Tree Integrity Protection**: All internal objects are individually hashed into leaves and rolled up into a root checksum for $O(1)$ whole-container validation.
* **Ed25519 Digital Signatures**: Optional public-key cryptographic signing of the Merkle root for author verification and non-repudiation.
* **Embedded Metadata Objects**: Preserves original filenames, MIME types, file sizes, and object numbers in Object 0 without altering the 72-byte header.
* **Magic-Byte MIME Detection**: Validates genuine file types by inspecting binary file signatures (PNG, JPEG, PDF, ZIP, MP3, MP4) rather than blindly trusting file extensions.
* **Byte-for-Byte Exact Round-Trip**: Encapsulating a file into `.stmf` and extracting it produces the exact identical binary file.
* **Modern Localhost Web App & Viewer**: Single-page application for creating, inspecting, verifying, and previewing verified media in real-time.
* **Tamper-Gated Security**: Untrusted or tampered containers are strictly blocked from rendering in the viewer or writing extracted files to disk.
* **Multi-Platform CLI**: Command-line tool for headless operations, batch conversions, and automated key generation.

---

## 📦 Container Binary Layout

```text
┌────────────────────────────────────────────────────────────────────────┐
│ 1. STM Header (Fixed 72 Bytes)                                         │
│    ├── Magic Bytes: "STM\x01\x00\x00\x00"                              │
│    ├── Container Version (u32) & Header Length (u32)                  │
│    ├── Total Length (u64)                                              │
│    └── Merkle Root Checksum (32 Bytes SHA-256)                         │
├────────────────────────────────────────────────────────────────────────┤
│ 2. Directory Table                                                     │
│    ├── Object Count (u64)                                              │
│    └── Canonical OID Entries (OID, Type, Offset, Length, Flags)        │
├────────────────────────────────────────────────────────────────────────┤
│ 3. Object Payloads                                                     │
│    ├── Object 0: JSON Metadata (Filename, Verified MIME, Size, OID)    │
│    └── Object 1: Original Raw File Payload (Byte-for-byte exact)       │
├────────────────────────────────────────────────────────────────────────┤
│ 4. Optional Signature Block (96 Bytes)                                 │
│    ├── Ed25519 Public Key (32 Bytes)                                   │
│    └── Merkle Root Digital Signature (64 Bytes)                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Architecture

The STM workspace consists of modular, single-responsibility Rust crates:

| Crate | Purpose |
| :--- | :--- |
| [`crates/stm-core`](crates/stm-core) | Core data primitives, OID definitions, `ObjectType` constants, and error types. |
| [`crates/stm-binary`](crates/stm-binary) | 72-byte header serialization, deserialization, and magic byte validation. |
| [`crates/stm-container`](crates/stm-container) | Canonical directory indexing, OID sorting, bounds checking, and binary search. |
| [`crates/stm-crypto`](crates/stm-crypto) | SHA-256 leaf computation and binary Merkle tree root construction. |
| [`crates/stm-signature`](crates/stm-signature) | Ed25519 key generation, Merkle root signing, and signature verification. |
| [`crates/stm-writer`](crates/stm-writer) | Low-level STM container builder and binary assembler. |
| [`crates/stm-parser`](crates/stm-parser) | Container parser, directory validator, integrity auditor, and object extractor. |
| [`crates/stm-file`](crates/stm-file) | High-level file-to-STMF converter, magic-byte MIME detector, and extractor. |
| [`crates/stm-server`](crates/stm-server) | Localhost Axum web server and dark-themed media viewer SPA. |
| [`crates/stm-cli`](crates/stm-cli) | Terminal CLI for key generation, file conversion, inspection, and verification. |

---

## 🚀 Quick Start

### 1. Build and Test Workspace
```powershell
# Format codebase
cargo fmt

# Verify compilation across all workspace crates
cargo check --workspace

# Run full automated test suite
cargo test --workspace
```

---

## 🌐 Running the Localhost Web Viewer

Start the local web server:
```powershell
cargo run -p stm-server
```

Open your browser at:
👉 **[http://localhost:8080](http://localhost:8080)** *(or the active port displayed in terminal)*

### Available Web Features:
* **Create**: Drag and drop any file (photo, document, audio, video) and convert it to a signed or unsigned `.stmf` container.
* **Open / Viewer**: Drag and drop an `.stmf` file to verify its Merkle integrity and digital signature, then preview verified media (PNG/JPEG images, MP4 videos, MP3/WAV audio, PDF documents, or formatted JSON/text).
* **Verify**: View detailed security and cryptographic validation reports.
* **Inspect**: Audit container internals including binary directory offsets, object sizes, Merkle roots, and embedded metadata.

---

## 💻 CLI Usage Guide

The `stm-cli` crate provides command-line control over all container operations:

### 1. Generate Ed25519 Keypair
```powershell
cargo run -p stm-cli -- keygen keys
```
Generates `keys/private.key` and `keys/public.key`.

### 2. Convert a File to STM Container (`file-create`)
```powershell
# Unsigned container
cargo run -p stm-cli -- file-create photo.png --output photo.stmf

# Digitally signed container
cargo run -p stm-cli -- file-create photo.png --output photo.stmf --signed --key keys/private.key
```

### 3. Verify Container Integrity (`verify`)
```powershell
cargo run -p stm-cli -- verify photo.stmf
```
**Output for valid container:**
```text
STM Container Verification
File: photo.stmf
Merkle Integrity: VALID
Signed: YES
Digital Signature: VALID
Result: VALID
```

### 4. Inspect Container Internals (`inspect` & `list`)
```powershell
cargo run -p stm-cli -- inspect photo.stmf
cargo run -p stm-cli -- list photo.stmf
```

### 5. Extract Original File (`extract`)
```powershell
cargo run -p stm-cli -- extract photo.stmf --output extracted/
```

---

## 🔒 Security Model & Tamper Detection

STM guarantees three levels of protection:

| Scenario | Merkle Integrity | Signature Status | Action Taken |
| :--- | :---: | :---: | :--- |
| **Authentic Signed Container** | `VALID` | `VALID` | Verified, extraction & live preview allowed. |
| **Authentic Unsigned Container** | `VALID` | `NOT PRESENT` | Verified, extraction & live preview allowed. |
| **Payload Modified in Transit** | `INVALID` | — | **Blocked**: Merkle mismatch, preview & extraction rejected. |
| **Signature Modified / Forged** | `VALID` | `INVALID` | **Blocked**: Signature failure, preview & extraction rejected. |

---

## 🧪 Automated Testing

STM comes with comprehensive test coverage:
* **Header tests**: Fixed 72-byte size, round-trip serialization, magic byte validation.
* **Directory tests**: Canonical sorting, binary search lookups, object bound validation.
* **Merkle tests**: Single leaf, multi-leaf duplicate-last rules, tampered leaf detection.
* **File type tests**: Magic byte signature detection for PNG, JPEG, PDF, ZIP, MP3, MP4.
* **Round-trip tests**: Byte-for-byte exact file recovery after conversion.
* **Anti-tamper tests**: Modifying container bytes explicitly rejects extraction.

Run all tests:
```powershell
cargo test --workspace
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).