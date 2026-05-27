package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
)

// encryptedFields lists the four sensitive columns that the utility will
// transform. Every other column passes through unchanged.
var encryptedFields = []string{"customer_id", "account_number", "request", "response"}

const markerIDColumn = "marker_id"

// ProcessCSV streams the input CSV row-by-row, transforming the four target
// fields according to mode ("encrypt" or "decrypt"), and writes the result to
// outputPath. It returns the number of data rows processed (excluding header)
// so callers — primarily the audit logger — can record it.
//
// Behaviour summary:
//   - In encrypt mode the four target fields are AES-256-CBC encrypted and a
//     marker_id column (SHA256 of the original plaintext customer_id) is
//     added/updated.
//   - In decrypt mode the four target fields are decrypted; marker_id is
//     passed through untouched.
//   - Missing target columns produce a single warning on stderr and are
//     silently skipped.
//   - Empty cells in target columns are passed through unchanged in both
//     directions and are NOT treated as errors.
//   - Per-cell failures produce a warning on stderr, an empty string in the
//     output cell, and processing continues.
//   - After the writer is flushed, the output file is re-opened and verified:
//     header columns must match what we wrote, and the data-row count must
//     match the input. A mismatch is treated as an error.
//   - The summary line is printed to stderr at the end.
func ProcessCSV(key []byte, inputPath, outputPath, mode string) (int, error) {
	if mode != "encrypt" && mode != "decrypt" {
		return 0, fmt.Errorf("invalid csv mode: %s", mode)
	}

	in, err := os.Open(inputPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open input CSV: %w", err)
	}
	defer in.Close()

	out, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("failed to create output CSV: %w", err)
	}
	defer out.Close()

	reader := csv.NewReader(in)
	reader.FieldsPerRecord = -1 // tolerate ragged rows; we won't trust them blindly
	writer := csv.NewWriter(out)

	header, err := reader.Read()
	if err == io.EOF {
		return 0, fmt.Errorf("input CSV is empty")
	}
	if err != nil {
		return 0, fmt.Errorf("failed to read CSV header: %w", err)
	}

	// Build a lookup of column name -> index for the header row.
	colIndex := make(map[string]int, len(header))
	for i, name := range header {
		colIndex[strings.TrimSpace(name)] = i
	}

	// Determine which of the four target columns are present.
	presentFields := make([]string, 0, len(encryptedFields))
	for _, f := range encryptedFields {
		if _, ok := colIndex[f]; ok {
			presentFields = append(presentFields, f)
		} else {
			fmt.Fprintf(os.Stderr, "warning: column %s not found in CSV header, skipping\n", f)
		}
	}

	// In encrypt mode ensure a marker_id column exists in the output header.
	// We never overwrite the user's existing marker_id index — if the column
	// is already there we'll update it in place. If not, we append it.
	outHeader := append([]string(nil), header...)
	markerIdx, markerExists := colIndex[markerIDColumn]
	customerIdx, customerPresent := colIndex["customer_id"]

	if mode == "encrypt" && !markerExists {
		outHeader = append(outHeader, markerIDColumn)
		markerIdx = len(outHeader) - 1
	}

	if err := writer.Write(outHeader); err != nil {
		return 0, fmt.Errorf("failed to write CSV header: %w", err)
	}

	var (
		rowNum   int
		warnings int
	)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return rowNum, fmt.Errorf("failed to read row %d: %w", rowNum+1, err)
		}
		rowNum++

		// Normalize the record length to the output header width so that we
		// can safely index into it (the input CSV might be shorter when we
		// added marker_id, or ragged).
		if len(record) < len(outHeader) {
			padded := make([]string, len(outHeader))
			copy(padded, record)
			record = padded
		}

		// In encrypt mode, capture the original plaintext customer_id BEFORE
		// we transform it so that marker_id is the SHA256 of the original.
		var originalCustomerID string
		if mode == "encrypt" && customerPresent && customerIdx < len(record) {
			originalCustomerID = record[customerIdx]
		}

		for _, field := range presentFields {
			idx := colIndex[field]
			if idx >= len(record) {
				continue
			}
			cell := record[idx]
			if cell == "" {
				// Empty cells pass through unchanged in both directions.
				continue
			}

			switch mode {
			case "encrypt":
				ct, encErr := Encrypt(key, cell)
				if encErr != nil {
					warnings++
					fmt.Fprintf(os.Stderr, "field %s row %d: encryption failed: %v\n", field, rowNum, encErr)
					record[idx] = ""
					continue
				}
				record[idx] = ct
			case "decrypt":
				pt, decErr := Decrypt(key, cell)
				if decErr != nil {
					warnings++
					low := strings.ToLower(decErr.Error())
					switch {
					case strings.Contains(low, "base64"):
						fmt.Fprintf(os.Stderr, "field %s row %d: base64 decode failed: %v\n", field, rowNum, decErr)
					case strings.Contains(low, "ciphertext too short"):
						fmt.Fprintf(os.Stderr, "field %s: ciphertext too short to contain IV (row %d)\n", field, rowNum)
					default:
						fmt.Fprintf(os.Stderr, "field %s row %d: decryption failed — wrong key or corrupted ciphertext\n", field, rowNum)
					}
					record[idx] = ""
					continue
				}
				record[idx] = pt
			}
		}

		// In encrypt mode, write marker_id from the captured original
		// customer_id. If customer_id was missing or empty, we leave
		// marker_id blank (or untouched if the user provided it).
		if mode == "encrypt" && customerPresent && originalCustomerID != "" {
			record[markerIdx] = HashSHA256(originalCustomerID)
		}

		if err := writer.Write(record); err != nil {
			return rowNum, fmt.Errorf("failed to write row %d: %w", rowNum, err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return rowNum, fmt.Errorf("failed to flush CSV writer: %w", err)
	}

	// Close output explicitly before verifying so all bytes are flushed to
	// disk (csv.Writer.Flush only flushes the buffered writer, not the file).
	if err := out.Close(); err != nil {
		return rowNum, fmt.Errorf("failed to close output CSV: %w", err)
	}

	if err := verifyOutputCSV(outputPath, rowNum, outHeader); err != nil {
		return rowNum, err
	}

	fmt.Fprintf(os.Stderr, "Processed %d rows. Fields operated on: %v. Warnings: %d\n",
		rowNum, presentFields, warnings)

	return rowNum, nil
}

// verifyOutputCSV re-opens the just-written output file and confirms:
//  1. its header matches the one we wrote, and
//  2. it contains exactly `expectedRows` data rows.
//
// This is a belt-and-suspenders check against partial writes caused by disk
// full, permission errors, or filesystem hiccups that csv.Writer.Flush did
// not surface. Any mismatch is fatal so we never silently hand Ops a
// truncated decrypted CSV.
func verifyOutputCSV(path string, expectedRows int, expectedHeader []string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("output verification failed: cannot reopen %s: %w", path, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1

	gotHeader, err := r.Read()
	if err == io.EOF {
		return fmt.Errorf("output verification failed: output file is empty")
	}
	if err != nil {
		return fmt.Errorf("output verification failed: cannot read header: %w", err)
	}
	if !equalStringSlices(gotHeader, expectedHeader) {
		return fmt.Errorf("output verification failed: header mismatch. expected %v, got %v", expectedHeader, gotHeader)
	}

	count := 0
	for {
		_, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("output verification failed: error reading row %d: %w", count+1, err)
		}
		count++
	}

	if count != expectedRows {
		return fmt.Errorf("Output verification failed: input had %d rows, output has %d rows", expectedRows, count)
	}
	return nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
