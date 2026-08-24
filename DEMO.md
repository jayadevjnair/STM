# STM — Demo & Testing Guide

This guide walks through testing all features of the **STM (Secure Trusted Media Container)** system, both via the CLI and through the web application.

---

## 🛠️ Step 1: Build and Run Workspace Tests

Verify that all crates compile and all automated unit and integration tests pass:

```powershell
# Format code
cargo fmt

# Workspace check
cargo check --workspace

# Run all automated tests
cargo test --workspace
```

---

## 💻 Step 2: Command-Line Interface (CLI) Demo

### 1. Generate an Ed25519 Keypair
```powershell
cargo run -p stm-cli -- keygen keys
```
*Creates `keys/private.key` and `keys/public.key`.*

---

### 2. Create a Sample File
Create a quick test text or binary file:
```powershell
Set-Content -Path "sample.txt" -Value "This is a confidential trusted document."
```

---

### 3. Convert Sample File to a Signed `.stmf` Container
```powershell
cargo run -p stm-cli -- file-create sample.txt --output sample.stmf --signed --key keys/private.key
```

**Expected Output:**
```text
Converted file to STM container
Input: sample.txt
Output: sample.stmf
Signed: YES
```

---

### 4. Verify the Container
```powershell
cargo run -p stm-cli -- verify sample.stmf
```

**Expected Output:**
```text
STM Container Verification
File: sample.stmf
Merkle Integrity: VALID
Signed: YES
Digital Signature: VALID
Result: VALID
```

---

### 5. Inspect Container Internals
```powershell
cargo run -p stm-cli -- inspect sample.stmf
cargo run -p stm-cli -- list sample.stmf
```

**Expected Output:**
```text
STM Container Inspection
File: sample.stmf
Version: 1.0
Total Length: 387 bytes
Objects: 2
Signed: YES
Signature: VALID
Merkle Root: [ ... ]
Merkle: VALID
State: VALID
```

---

### 6. Extract the Original File
```powershell
cargo run -p stm-cli -- extract sample.stmf --output extracted/
```
Verify that the file extracted to `extracted/sample.txt` matches the original content:
```powershell
Get-Content extracted/sample.txt
```

---

### 7. Tamper Detection Test (Simulating Attack)

Modify bytes inside `sample.stmf` using PowerShell to simulate file tampering:
```powershell
$bytes = [System.IO.File]::ReadAllBytes("sample.stmf")
$bytes[120] = $bytes[120] -bxor 0xFF
[System.IO.File]::WriteAllBytes("tampered.stmf", $bytes)
```

Now attempt to verify the tampered container:
```powershell
cargo run -p stm-cli -- verify tampered.stmf
```

**Expected Output:**
```text
STM Container Verification
File: tampered.stmf
Result: INVALID
Reason: Merkle root mismatch
```

Attempting to extract the tampered container will also be rejected:
```powershell
cargo run -p stm-cli -- extract tampered.stmf --output extracted_tampered/
```

---

## 🌐 Step 3: Localhost Web Application Demo

### 1. Launch the Server
```powershell
cargo run -p stm-server
```

Open your browser at: **[http://localhost:8080](http://localhost:8080)** (or the port listed in the console).

### 2. Test File Conversion (Create Tab)
1. Go to the **Create** tab in the left sidebar.
2. Drag and drop any photo (`.png`, `.jpg`), video (`.mp4`), audio (`.mp3`), or PDF.
3. Check **Sign container**.
4. Click **Convert to STMF**. The browser will automatically download the generated `.stmf` file.

### 3. Test Secure Viewer (Open / Viewer Tab)
1. Go to the **Open / Viewer** tab.
2. Drag and drop the downloaded `.stmf` file.
3. Observe the green security indicators:
   - `✓ Container Valid`
   - `✓ Merkle Integrity Valid`
   - `✓ Digital Signature Valid`
4. The media will preview directly (image rendering, audio/video player, or embedded PDF/text).
5. Click **Extract Original** to download the exact restored file.

### 4. Test Tamper Protection in the Web Viewer
1. Drag and drop `tampered.stmf` into the **Open / Viewer** tab.
2. Observe the red security indicator:
   - `✗ Container Invalid`
   - `✗ Merkle Root Mismatch`
3. Notice that the viewer **blocks the preview** and displays `Cannot preview untrusted container.`
