package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
)

// Version is printed by --version. Update before each build/distribution.
const Version = "1.0.0"

// Environment variable names that supply sensitive identifiers without
// putting them on the command line (where they leak into `ps aux`, shell
// history, audit trails outside our control, etc.).
//
// IMPORTANT: these env vars only carry IDENTIFIERS (the secret name, the
// project ID). They never carry the AES key itself — that remains
// Secret-Manager-only by design.
const (
	envSecretName = "OPS_CRYPTO_SECRET_NAME"
	envProject    = "OPS_CRYPTO_PROJECT"
)

var validModes = map[string]bool{
	"encrypt": true,
	"decrypt": true,
	"hash":    true,
}

var validFields = map[string]bool{
	"customer_id":    true,
	"account_number": true,
	"request":        true,
	"response":       true,
}

func main() {
	// run() encapsulates all real work so that audit.WriteAuditLog runs via
	// defer no matter how we exit. os.Exit bypasses defers, so we deliberately
	// call it only here, from the top frame.
	os.Exit(run(os.Args[1:]))
}

// run parses args, drives the operation, and returns the process exit code.
// 0 on success, 1 on any error. Every path through this function writes
// exactly one audit log line.
func run(args []string) int {
	var (
		project       string
		secretName    string
		secretVersion string
		mode          string
		field         string
		value         string
		csvInput      string
		csvOutput     string
		showVer       bool
	)

	fs := flag.NewFlagSet("ops-crypto-util", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&project, "project", "", "GCP project ID (or set "+envProject+")")
	fs.StringVar(&secretName, "secret-name", "", "Secret Manager secret name (or set "+envSecretName+")")
	fs.StringVar(&secretVersion, "secret-version", "latest", "Secret Manager version: \"latest\" or a numeric version")
	fs.StringVar(&mode, "mode", "", "Operation mode: encrypt | decrypt | hash (required)")
	fs.StringVar(&field, "field", "", "Field name for single value mode: customer_id | account_number | request | response")
	fs.StringVar(&value, "value", "", "Single plaintext or ciphertext value to process")
	fs.StringVar(&csvInput, "csv-input", "", "Path to input CSV file")
	fs.StringVar(&csvOutput, "csv-output", "", "Path to output CSV file")
	fs.BoolVar(&showVer, "version", false, "Print binary version and exit")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "ops-crypto-util %s — AES-256-CBC + SHA256 utility for Ops\n\n", Version)
		fmt.Fprintln(os.Stderr, "Usage:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if showVer {
		fmt.Println(Version)
		return 0
	}

	// Trim whitespace from --value early so accidental spaces from copy/paste
	// (very common when Ops paste BigQuery cells) do not corrupt
	// encrypt/decrypt input or skew base64 length checks.
	value = strings.TrimSpace(value)

	// Env-var fallback for sensitive identifiers. Precedence is the standard
	// Unix convention: an explicit CLI flag wins, env var is the fallback,
	// default ("") is the failure case caught by validateFlags below.
	//
	// This lets jump-server admins set OPS_CRYPTO_SECRET_NAME (and optionally
	// OPS_CRYPTO_PROJECT) in /etc/profile.d so Ops never have to type the
	// secret name on the command line, where it would leak into `ps aux`,
	// shell history and other process inventories.
	if secretName == "" {
		secretName = strings.TrimSpace(os.Getenv(envSecretName))
	}
	if project == "" {
		project = strings.TrimSpace(os.Getenv(envProject))
	}

	// Build the audit record as soon as we have anything to record so even
	// validation failures and crashes are auditable. Status defaults to
	// "failure" in NewAuditRecord; we flip it to "success" only on the happy
	// path.
	rec := NewAuditRecord()
	rec.Mode = mode
	rec.Project = project
	rec.SecretName = secretName
	if secretVersion != "" {
		rec.SecretVersion = secretVersion
	}
	switch {
	case csvInput != "":
		rec.InputType = "csv"
	case value != "":
		rec.InputType = "single_value"
		rec.Field = field
	}
	defer WriteAuditLog(rec)

	errs := validateFlags(project, secretName, mode, field, value, csvInput, csvOutput)
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, e)
		}
		fs.Usage()
		rec.Error = strings.Join(errs, "; ")
		return 1
	}

	ctx := context.Background()
	key, err := LoadKey(ctx, project, secretName, secretVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		rec.Error = err.Error()
		return 1
	}
	// Best-effort wipe of the key bytes from memory before this frame exits.
	// Go can copy the slice internally so this is not bullet-proof, but it
	// covers the obvious case and costs almost nothing.
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	rows, err := dispatch(key, mode, field, value, csvInput, csvOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		rec.Error = err.Error()
		// Even on failure, record any rows we did process so auditors can
		// tell how far we got before the failure.
		if rows > 0 {
			rec.RowsProcessed = rows
		}
		return 1
	}

	if csvInput != "" {
		rec.RowsProcessed = rows
	}
	rec.Status = "success"
	return 0
}

// validateFlags applies all CLI validation rules and returns every violation
// as a separate string so the caller can show them all at once.
func validateFlags(project, secretName, mode, field, value, csvInput, csvOutput string) []string {
	var errs []string

	if strings.TrimSpace(project) == "" {
		errs = append(errs, "--project is required (or set "+envProject+")")
	}
	if strings.TrimSpace(secretName) == "" {
		errs = append(errs, "--secret-name is required (or set "+envSecretName+")")
	}
	if strings.TrimSpace(mode) == "" {
		errs = append(errs, "--mode is required")
	} else if !validModes[mode] {
		errs = append(errs, fmt.Sprintf("--mode must be one of: encrypt, decrypt, hash (got %q)", mode))
	}

	if value != "" && csvInput != "" {
		errs = append(errs, "--value and --csv-input are mutually exclusive")
	}

	if value == "" && csvInput == "" {
		errs = append(errs, "either --value or --csv-input must be provided")
	}

	if csvInput != "" && csvOutput == "" {
		errs = append(errs, "--csv-output is required when --csv-input is set")
	}

	if mode == "hash" && csvInput != "" {
		errs = append(errs, "hash mode only supports --value, not --csv-input")
	}

	if value != "" && mode != "hash" && mode != "" {
		if strings.TrimSpace(field) == "" {
			errs = append(errs, "--field is required when --value is set (except in hash mode)")
		} else if !validFields[field] {
			errs = append(errs, fmt.Sprintf("--field must be one of: customer_id, account_number, request, response (got %q)", field))
		}
	}

	return errs
}

// dispatch routes the validated invocation to the correct handler. By this
// point we know either --value or --csv-input is set, but never both. It
// returns the number of rows processed (CSV mode only; 0 otherwise) and any
// fatal error.
func dispatch(key []byte, mode, field, value, csvInput, csvOutput string) (int, error) {
	switch {
	case csvInput != "":
		return ProcessCSV(key, csvInput, csvOutput, mode)
	case mode == "hash":
		fmt.Println(HashSHA256(value))
		return 0, nil
	case mode == "encrypt":
		ct, err := Encrypt(key, value)
		if err != nil {
			return 0, fmt.Errorf("encryption failed for field %s: %w", field, err)
		}
		fmt.Println(ct)
		return 0, nil
	case mode == "decrypt":
		pt, err := Decrypt(key, value)
		if err != nil {
			low := strings.ToLower(err.Error())
			switch {
			case strings.Contains(low, "base64"):
				return 0, fmt.Errorf("decode failed for field %s: %w", field, err)
			case strings.Contains(low, "ciphertext too short"):
				return 0, fmt.Errorf("field %s: ciphertext too short to contain IV", field)
			default:
				return 0, fmt.Errorf("decryption failed for field %s: wrong key or corrupted ciphertext", field)
			}
		}
		fmt.Println(pt)
		return 0, nil
	}
	return 0, fmt.Errorf("unhandled invocation")
}
