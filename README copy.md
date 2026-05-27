# ops-crypto-util

Internal CLI utility for the Ops team to encrypt, decrypt and hash sensitive
fields stored in BigQuery (`customer_id`, `account_number`, `request`,
`response`). The AES key never leaves Google Cloud Secret Manager and is
fetched on every invocation. Every execution writes one JSON line to an
on-disk audit log so auditors can answer "who decrypted what, when?" from a
single file.

- **Algorithm:** AES-256-CBC, PKCS5 padding (wire-compatible with Java's `AES/CBC/PKCS5Padding`)
- **IV:** Random 16 bytes per encryption, prepended to ciphertext, the whole blob Base64 encoded
- **Key source:** GCP Secret Manager (`projects/{project}/secrets/{secret}/versions/{version}`)
- **Marker:** `marker_id = SHA256(customer_id)` (lowercase hex) — plaintext, used for BigQuery lookups
- **Audit log:** one JSON line per invocation, appended to `/var/log/ops-crypto-util/audit.log`

Because the IV is random, encrypting the same plaintext twice produces two
different ciphertexts. This is intentional. The `marker_id` field is what
gives Ops a deterministic handle for searching BigQuery without exposing PII.

---

## Project layout

```
ops-crypto-util/
├── main.go                    CLI entrypoint, flag parsing, mode routing
├── crypto.go                  Encrypt, Decrypt, pkcs5Pad/Unpad, HashSHA256
├── secretmanager.go           GCP Secret Manager key loading
├── csvprocessor.go            CSV stream-read, process, stream-write, verify
├── audit.go                   JSON-lines audit logger
├── crypto_test.go             Tests for crypto.go
├── csvprocessor_test.go       Tests for csvprocessor.go (round-trip + verify)
├── audit_test.go              Tests for audit.go
├── go.mod
├── go.sum
└── README.md
```

---

## Prerequisites

- **Go 1.25.3** on the build host (the toolchain auto-upgrades to whatever the
  GCP SDK requires; on the build host you just need Go installed and network
  access to the Go module proxy)
- **GCP service account JSON** with `roles/secretmanager.secretAccessor` on
  the secret
- **Outbound HTTPS** to `secretmanager.googleapis.com` from the jump server

### Environment variables

To keep sensitive identifiers off the command line (where they would leak
into `ps aux`, shell history and other process inventories), the tool reads
two optional env vars and falls back to them whenever the matching flag is
empty:

| Env var | Replaces flag | Notes |
|---|---|---|
| `OPS_CRYPTO_PROJECT` | `--project` | GCP project ID |
| `OPS_CRYPTO_SECRET_NAME` | `--secret-name` | Name of the Secret Manager secret holding the AES key |

Recommended setup on a jump server (one-time):

```bash
# /etc/profile.d/ops-crypto-util.sh — runs for every Ops shell
export GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/ops-sa.json
export OPS_CRYPTO_PROJECT=my-gcp-project
export OPS_CRYPTO_SECRET_NAME=aes-ops-key
```

After this, day-to-day Ops commands collapse to just the action being
performed, e.g. `ops-crypto-util --mode hash --value "CUST123456"` — no
secret name or project ID is ever typed at the prompt.

If both an env var and the matching flag are set, the **flag wins** (standard
12-factor precedence). The actual AES key bytes are still fetched only from
Secret Manager; the env vars only carry identifiers, never the key itself.

---

## How the key should be stored in Secret Manager

Generate a random 32-byte key and Base64 encode it:

```bash
openssl rand -base64 32
```

Store that Base64 string as the secret payload in Secret Manager. The tool
will Base64 decode the payload to recover the raw 32 bytes and will refuse
any key that does not decode to exactly 32 bytes.

```bash
# Create a fresh secret (first time only)
openssl rand -base64 32 | \
  gcloud secrets create aes-ops-key --data-file=- --project=my-gcp-project

# Add a new version on an existing secret (during rotation)
openssl rand -base64 32 | \
  gcloud secrets versions add aes-ops-key --data-file=- --project=my-gcp-project
```

The tool **strictly** validates that the decoded key is exactly 32 bytes. Any
other length is a fatal error with the message `invalid key length: got N
bytes, want 32`.

---

## Build

```bash
# Build for Linux amd64 jump server
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ops-crypto-util .

# Build for Mac (local testing)
go build -ldflags="-s -w" -o ops-crypto-util .

# Distribute binary to jump server
scp ops-crypto-util user@jump-server:/usr/local/bin/ops-crypto-util
ssh user@jump-server "chmod +x /usr/local/bin/ops-crypto-util"

# Set GCP credentials on jump server
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json

# Test: hash a customer ID
ops-crypto-util \
  --project my-gcp-project \
  --secret-name aes-ops-key \
  --mode hash \
  --value "CUST123456"
```

The `-s -w` linker flags strip the symbol table and DWARF debug info, which
keeps the binary lean and makes reverse-engineering slightly less convenient.

---

## CLI reference

| Flag | Type | Description |
|---|---|---|
| `--project` | string | GCP project ID. Falls back to env var `OPS_CRYPTO_PROJECT`. |
| `--secret-name` | string | Secret Manager secret name. Falls back to env var `OPS_CRYPTO_SECRET_NAME`. |
| `--secret-version` | string | Secret version: `latest` or a numeric version (default `latest`) |
| `--mode` | string | `encrypt`, `decrypt`, or `hash` (required) |
| `--field` | string | One of `customer_id`, `account_number`, `request`, `response` (required when `--value` is set, except in `hash` mode) |
| `--value` | string | Single plaintext/ciphertext value to process (whitespace is trimmed before processing) |
| `--csv-input` | string | Path to input CSV file |
| `--csv-output` | string | Path to output CSV file (required with `--csv-input`) |
| `--version` | flag | Print binary version and exit |

Rules:

- `--value` and `--csv-input` are mutually exclusive
- `--csv-output` is required whenever `--csv-input` is set
- `hash` mode only accepts `--value`, never `--csv-input`
- `--value` is trimmed of leading/trailing whitespace before use
- Errors go to **stderr**; the result (single value, marker_id hash) goes to **stdout**
- Exit code `0` on success, `1` on any error
- The AES key is **never** printed, logged, or written to disk

---

## Usage examples

### Encrypt a single customer_id

```bash
./ops-crypto-util \
  --project my-gcp-project \
  --secret-name aes-ops-key \
  --mode encrypt \
  --field customer_id \
  --value "CUST123456"
```

Output: a Base64 string of `IV || ciphertext`.

### Decrypt a single value

```bash
./ops-crypto-util \
  --project my-gcp-project \
  --secret-name aes-ops-key \
  --mode decrypt \
  --field account_number \
  --value "BASE64CIPHERTEXTHERE"
```

### Decrypt with an older key version (during rotation)

```bash
./ops-crypto-util \
  --project my-gcp-project \
  --secret-name aes-ops-key \
  --secret-version 4 \
  --mode decrypt \
  --field customer_id \
  --value "BASE64CIPHERTEXTHERE"
```

### Hash a customer_id to get marker_id

```bash
./ops-crypto-util \
  --project my-gcp-project \
  --secret-name aes-ops-key \
  --mode hash \
  --value "CUST123456"
```

### Decrypt every sensitive field in a CSV

```bash
./ops-crypto-util \
  --project my-gcp-project \
  --secret-name aes-ops-key \
  --mode decrypt \
  --csv-input /tmp/records.csv \
  --csv-output /tmp/decrypted_records.csv
```

### Encrypt every sensitive field in a CSV

```bash
./ops-crypto-util \
  --project my-gcp-project \
  --secret-name aes-ops-key \
  --mode encrypt \
  --csv-input /tmp/records.csv \
  --csv-output /tmp/records_encrypted.csv
```

The output CSV is identical in shape to the input, except:

- Cells in `customer_id`, `account_number`, `request`, `response` are
  replaced with their encrypted (or decrypted) equivalent
- In encrypt mode, a `marker_id` column is added (or its existing value
  updated) holding `SHA256(original_plaintext_customer_id)`
- Missing columns produce a warning on stderr and are silently skipped
- Empty cells pass through unchanged (no error, no ciphertext written)
- Per-cell decryption failures produce a warning on stderr, write an empty
  string into the cell, and processing continues

A summary line goes to stderr at the end:

```
Processed N rows. Fields operated on: [customer_id account_number request response]. Warnings: W
```

---

## CSV row-level behaviour

The CSV processor uses Go's `encoding/csv` reader/writer and streams one row
at a time — it does **not** buffer the entire file in memory, so it works on
multi-GB exports from BigQuery without OOMing the jump server.

- **Encrypt mode:** the original plaintext `customer_id` is captured before
  it is encrypted, so `marker_id = SHA256(plaintext customer_id)` even after
  the column itself is overwritten with ciphertext.
- **Empty cells** pass through unchanged in both directions. No encryption,
  decryption or hashing is applied to blank values.
- **Ragged rows** (rows shorter than the header) are right-padded with empty
  strings so the output is always a clean rectangle.

### Output verification

After the writer is flushed and the output file closed, the file is re-opened
and verified:

- **Header check:** the header row in the output file must exactly match the
  header the tool intended to write (including the `marker_id` column in
  encrypt mode).
- **Row-count check:** the number of data rows in the output file must
  exactly equal the number of data rows read from the input.

Any mismatch is fatal with a message like:

```
Output verification failed: input had N rows, output has M rows
```

This guards Ops against silently handing off a truncated decrypted CSV when
the disk filled up mid-write or a network share dropped the connection.

---

## Audit logging

Every invocation appends exactly one JSON line to:

```
/var/log/ops-crypto-util/audit.log
```

The directory is created with `0755` if missing; the log file itself is
created with mode `0640` (owner read/write, group read, world none) and is
**append-only** — the CLI never truncates it. Rotation should be left to
`logrotate(8)`.

If the audit write fails for any reason (permissions, full disk, missing
mount), the failure is reported as a single stderr warning and the
encrypt/decrypt operation still completes. We never let a broken audit
pipeline block Ops from decrypting customer data during an incident.

### Log line format

```json
{
  "timestamp": "2026-05-27T10:32:00Z",
  "user": "alice",
  "hostname": "jump-1",
  "mode": "decrypt",
  "input_type": "single_value",
  "field": "customer_id",
  "secret_name": "aes-ops-key",
  "secret_version": "latest",
  "project": "my-gcp-project",
  "status": "success",
  "error": ""
}
```

- `timestamp` — UTC, RFC3339
- `user` — OS username from `os/user`
- `hostname` — machine hostname
- `mode` — `encrypt` / `decrypt` / `hash`
- `input_type` — `csv` or `single_value`
- `field` — set only in single-value mode
- `rows_processed` — set only in CSV mode
- `secret_name` / `secret_version` / `project` — key provenance for auditors
- `status` — `success` or `failure`
- `error` — populated on failure

The audit record **never** contains the plaintext value, the ciphertext
value, the marker hash, or any byte of the AES key. It is strictly metadata.

---

## BigQuery lookup workflow for Ops

1. **Get the customer_id** from the customer complaint ticket.
2. **Hash it** to produce the deterministic marker:

   ```bash
   ops-crypto-util \
     --project my-gcp-project \
     --secret-name aes-ops-key \
     --mode hash \
     --value "CUST123456"
   ```

3. **Query BigQuery** with the hash:

   ```sql
   SELECT *
   FROM `my-gcp-project.banking_logs.api_events`
   WHERE marker_id = '<paste hash here>'
   ORDER BY event_timestamp DESC
   LIMIT 50;
   ```

4. **Export the result** as CSV with at least the columns `customer_id`,
   `account_number`, `request`, `response`, and `marker_id`. Save it as
   `/tmp/records.csv` on the jump server.
5. **Decrypt the CSV** with the tool:

   ```bash
   ops-crypto-util \
     --project my-gcp-project \
     --secret-name aes-ops-key \
     --mode decrypt \
     --csv-input /tmp/records.csv \
     --csv-output /tmp/decrypted.csv
   ```

6. **Inspect `decrypted.csv`** to debug the customer's request/response.
   When you're done, delete `/tmp/decrypted.csv` — it contains plaintext PII.

---

## Key rotation runbook

The `--secret-version` flag exists specifically to support rotation. The
strategy: rotate forward at the writer pipeline, and decrypt with an explicit
version for any record that pre-dates the rotation.

1. **Generate a new key version** in Secret Manager:

   ```bash
   openssl rand -base64 32 | \
     gcloud secrets versions add aes-ops-key \
       --data-file=- --project=my-gcp-project
   ```

   Note the new version number (e.g. `5`).

2. **Roll the writer pipeline** (the service that publishes API events into
   Pub/Sub → BigQuery) so it picks up `versions/latest` and starts encrypting
   new records under version 5. From this point onwards, all *new* records in
   BigQuery are encrypted with version 5.

3. **For decrypting historical records** encrypted under an older version:

   ```bash
   # Decrypt a record that was written before the rotation
   ops-crypto-util \
     --project my-gcp-project \
     --secret-name aes-ops-key \
     --secret-version 4 \
     --mode decrypt \
     --csv-input /tmp/old_records.csv \
     --csv-output /tmp/old_decrypted.csv
   ```

4. **Optional re-encryption** (if required by your data retention policy):
   decrypt with the old version and re-encrypt with the new one, writing the
   updated rows back to BigQuery. This is a back-fill job; do not run it
   ad-hoc on the jump server.

5. **Disable, do not destroy, the old version** until you are confident no
   record encrypted under it remains in BigQuery. Destroyed versions cannot
   be recovered.

---

## Permissions required on the jump server

| Path / resource | Permission |
|---|---|
| `$GOOGLE_APPLICATION_CREDENTIALS` (service account JSON) | Read |
| `/var/log/ops-crypto-util/` | Write (for audit logs) |
| `--csv-input` path | Read |
| `--csv-output` path | Write |
| Outbound HTTPS to `secretmanager.googleapis.com:443` | Allowed |

The first time the tool runs it will create `/var/log/ops-crypto-util/` with
mode `0755`. Either pre-create that directory and grant `g+w` to the Ops
group, or run the tool as a user/group that can write under `/var/log`.

---

## What to do if decryption fails

| Symptom | Cause | Action |
|---|---|---|
| `decryption failed for field X: wrong key or corrupted ciphertext` | The record was encrypted under a different key version | Retry with `--secret-version <N>` for an older version. Walk versions backwards from `latest`. |
| `decryption failed for field X: wrong key or corrupted ciphertext` (and no other version works) | The ciphertext bytes were corrupted (truncated, mangled by a Unicode-aware copy/paste, etc.) | Flag the BigQuery row for investigation. Confirm the source bytes match what BigQuery stored. |
| `secret manager access denied: check service account IAM permissions` | The service account lost `roles/secretmanager.secretAccessor` on the secret | Have IAM re-grant the role. Verify with `gcloud secrets versions access latest --secret=aes-ops-key`. |
| `invalid key length: got N bytes, want 32` | The secret payload is not a 32-byte key encoded in Base64 | Re-create the secret version using `openssl rand -base64 32`. |
| `ciphertext too short: need at least 24 base64 chars` | Empty or truncated input passed to `--value` | Check the value isn't accidentally empty after the shell stripped quotes. |
| `Output verification failed: input had N rows, output has M rows` | Disk full or permissions issue mid-write | Free disk space / fix permissions on `--csv-output` and re-run. The partial file should be discarded. |

---

## Errors at a glance

| Situation | Message |
|---|---|
| Key not 32 bytes | `invalid key length: got N bytes, want 32` |
| Secret Manager IAM denial | `secret manager access denied: check service account IAM permissions` |
| Base64 decode failure (single value) | `decode failed for field <field>: <err>` |
| Base64 decode failure (CSV) | `field <field> row <N>: base64 decode failed: <err>` |
| Wrong key / corrupt data (single value) | `decryption failed for field <field>: wrong key or corrupted ciphertext` |
| Wrong key / corrupt data (CSV) | `field <field> row <N>: decryption failed — wrong key or corrupted ciphertext` |
| CSV column missing | `warning: column <name> not found in CSV header, skipping` |
| Mutually exclusive flags | `--value and --csv-input are mutually exclusive` |
| Missing required flag | `--<flag> is required` |
| Hash mode with CSV input | `hash mode only supports --value, not --csv-input` |
| Ciphertext too short | `ciphertext too short: need at least 24 base64 chars (16-byte IV), got <N>` |
| Output verification failure | `Output verification failed: input had N rows, output has M rows` |

---

## Input sanitization

- `--value` is trimmed of leading/trailing whitespace before any operation,
  so accidental spaces from copy-paste do not corrupt encrypt/decrypt input.
- `Encrypt` rejects empty plaintext with a clear error.
- `Decrypt` rejects Base64 strings shorter than 24 characters (the minimum
  length needed to encode a 16-byte IV) before attempting any AES work.
- Empty CSV cells in target columns are passed through unchanged in both
  directions and are **not** treated as errors.

---

## Security notes

- **No network listeners.** The binary opens no ports, exposes no API and
  starts no server. It only talks outbound to Secret Manager via the standard
  Google API endpoint.
- **No env-var key.** The AES key cannot be supplied via flag or env var —
  Secret Manager is the only source. The supported env vars (`OPS_CRYPTO_PROJECT`,
  `OPS_CRYPTO_SECRET_NAME`) carry only identifiers, never the key bytes.
- **No plaintext temp files.** Decrypted data is written only to
  `--csv-output`.
- **No key in logs.** The key bytes are never printed, logged, or written
  anywhere on disk. On exit the key buffer is overwritten with zeros
  (best-effort).
- **Audit log excludes PII.** The audit log records metadata only —
  who/when/what/how-many — never plaintext, ciphertext, marker, or key bytes.
- **`crypto/rand` for IV.** Math/rand is never used for any cryptographic
  material.
- **Separate destination on decrypt.** AES-CBC decryption writes into a
  freshly-allocated `plaintext` buffer rather than reusing the same slice
  that holds the IV + ciphertext, which removes a well-known foot-gun.
- **Java compatibility.** PKCS5 with AES's 16-byte block size is identical
  to PKCS7, so output is byte-for-byte interoperable with Java's
  `AES/CBC/PKCS5Padding`.

---

## Running the tests

```bash
go test ./...
```

The unit tests cover:

- PKCS5 padding/unpadding (including tampered-padding rejection)
- AES-256-CBC encrypt/decrypt round-trip with multi-block plaintexts
- Random-IV invariant (same input → different ciphertext)
- Wrong-key rejection
- Encrypt rejects empty plaintext
- Decrypt rejects short Base64
- SHA-256 output shape
- CSV round-trip (encrypt then decrypt restores all four target fields)
- CSV `marker_id` is computed from the **plaintext** `customer_id`
- CSV empty-cell pass-through
- CSV output verification catches truncated files and header mismatches
- Audit log writes valid JSON lines with correct `omitempty` behaviour
- Audit log failures degrade to a warning instead of crashing

None of the tests require GCP credentials.
