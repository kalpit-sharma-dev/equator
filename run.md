# ops-crypto-util — Run Commands

Quick command reference. Run everything from `d:\IIT\util\ops-crypto-util`.

---

## Build

```bash
# Windows (local testing)
go build -ldflags="-s -w" -o ops-crypto-util.exe .

# Linux jump server (cross-compile from Windows)
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ops-crypto-util .

# macOS
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o ops-crypto-util .
```

---

## Run the tests (no GCP credentials needed)

```bash
go vet ./...
go test ./... -count=1 -v
```

---

## Sanity checks that don't need GCP

```bash
# Print version
./ops-crypto-util.exe --version

# See all flags (validation prints all errors at once, then usage)
./ops-crypto-util.exe

# Run with help
./ops-crypto-util.exe -h
```

---

## Prepare GCP credentials (once, before encrypt/decrypt/hash modes)

```bash
# Windows (PowerShell)
$env:GOOGLE_APPLICATION_CREDENTIALS = "C:\path\to\sa-key.json"

# Windows (Git Bash / WSL)
export GOOGLE_APPLICATION_CREDENTIALS="/c/path/to/sa-key.json"

# Linux / macOS
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/sa-key.json"
```

The service account must hold `roles/secretmanager.secretAccessor` on the secret.

---

## Set sensitive identifiers via env vars (recommended on jump servers)

To keep the secret name and project ID off the command line (and out of
`ps aux` / shell history), export them once per shell instead of passing
flags every time:

```bash
# Linux / macOS / Git Bash
export OPS_CRYPTO_PROJECT="my-gcp-project"
export OPS_CRYPTO_SECRET_NAME="aes-ops-key"

# Windows (PowerShell)
$env:OPS_CRYPTO_PROJECT = "my-gcp-project"
$env:OPS_CRYPTO_SECRET_NAME = "aes-ops-key"
```

On the production jump server, put these in `/etc/profile.d/ops-crypto-util.sh`
so every Ops shell picks them up automatically. With these set, every
example below becomes shorter — just drop `--project` and `--secret-name`.

If both are set, `--project` / `--secret-name` flags **override** the env
vars (standard precedence). The AES key bytes themselves are still fetched
only from Secret Manager; these env vars carry only the identifiers.

---

## Set up the key in Secret Manager (one-time)

```bash
# Create a fresh 32-byte key, Base64 encode, push to Secret Manager
openssl rand -base64 32 | \
  gcloud secrets create aes-ops-key --data-file=- --project=my-gcp-project
```

---

## Hash a customer_id to get marker_id

With env vars set (recommended):

```bash
./ops-crypto-util.exe --mode hash --value "CUST123456"
```

Or with explicit flags:

```bash
./ops-crypto-util.exe \
  --project my-gcp-project \
  --secret-name aes-ops-key \
  --mode hash \
  --value "CUST123456"
```

Output (single line on stdout): the lowercase hex SHA-256, e.g.
`32212c5641a98aae71f4c08c1f5c2dec00c7f7ca15131c2c2c8c11b7b8e29ada`.

---

## Encrypt a single value

```bash
./ops-crypto-util.exe \
  --project my-gcp-project \
  --secret-name aes-ops-key \
  --mode encrypt \
  --field customer_id \
  --value "CUST123456"
```

Output (stdout): the Base64 of `IV || ciphertext`.

---

## Decrypt a single value

```bash
./ops-crypto-util.exe \
  --project my-gcp-project \
  --secret-name aes-ops-key \
  --mode decrypt \
  --field account_number \
  --value "BASE64CIPHERTEXTHERE"
```

---

## Decrypt with a non-latest key version (during rotation)

```bash
./ops-crypto-util.exe \
  --project my-gcp-project \
  --secret-name aes-ops-key \
  --secret-version 4 \
  --mode decrypt \
  --field customer_id \
  --value "BASE64CIPHERTEXTHERE"
```

---

## Decrypt a CSV exported from BigQuery

```bash
./ops-crypto-util.exe \
  --project my-gcp-project \
  --secret-name aes-ops-key \
  --mode decrypt \
  --csv-input  /tmp/records.csv \
  --csv-output /tmp/decrypted.csv
```

---

## Encrypt a CSV

```bash
./ops-crypto-util.exe \
  --project my-gcp-project \
  --secret-name aes-ops-key \
  --mode encrypt \
  --csv-input  /tmp/plain.csv \
  --csv-output /tmp/encrypted.csv
```

---

## Inspect the audit log

```bash
# Linux jump server (one JSON line per invocation)
tail -f /var/log/ops-crypto-util/audit.log

# Pretty-print the last 10 entries
tail -n 10 /var/log/ops-crypto-util/audit.log | jq .

# Find every decrypt run by user "alice"
jq -c 'select(.user=="alice" and .mode=="decrypt")' /var/log/ops-crypto-util/audit.log
```

---

## Quick end-to-end smoke test on Windows (no GCP)

If you just want to confirm the binary builds and validates correctly without
setting up any GCP infra:

```bash
go build -ldflags="-s -w" -o ops-crypto-util.exe .
./ops-crypto-util.exe --version
./ops-crypto-util.exe                  # should print all validation errors + usage, exit 1
go test ./... -count=1                 # full crypto + CSV + audit test suite
```
