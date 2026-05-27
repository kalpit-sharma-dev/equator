package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAuditLogAppendsJSONLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "audit.log")

	orig := auditLogPath
	auditLogPath = path
	t.Cleanup(func() { auditLogPath = orig })

	rec1 := &AuditRecord{
		Timestamp:  "2026-05-27T10:32:00Z",
		User:       "alice",
		Hostname:   "jump-1",
		Mode:       "decrypt",
		InputType:  "single_value",
		Field:      "customer_id",
		SecretName: "aes-ops-key",
		Project:    "my-gcp-project",
		Status:     "success",
	}
	rec2 := &AuditRecord{
		Timestamp:     "2026-05-27T10:33:00Z",
		User:          "bob",
		Hostname:      "jump-1",
		Mode:          "encrypt",
		InputType:     "csv",
		RowsProcessed: 42,
		SecretName:    "aes-ops-key",
		Project:       "my-gcp-project",
		Status:        "success",
	}

	WriteAuditLog(rec1)
	WriteAuditLog(rec2)

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("expected audit log at %s: %v", path, err)
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 audit lines, got %d", len(lines))
	}

	var got1 AuditRecord
	if err := json.Unmarshal([]byte(lines[0]), &got1); err != nil {
		t.Fatalf("line 1 not valid JSON: %v (%s)", err, lines[0])
	}
	if got1.User != "alice" || got1.Mode != "decrypt" || got1.Field != "customer_id" {
		t.Fatalf("unexpected record: %+v", got1)
	}
	// rows_processed omitempty should keep CSV-only field out of single_value records.
	if strings.Contains(lines[0], "rows_processed") {
		t.Fatalf("rows_processed should be omitted from single_value record: %s", lines[0])
	}

	var got2 AuditRecord
	if err := json.Unmarshal([]byte(lines[1]), &got2); err != nil {
		t.Fatalf("line 2 not valid JSON: %v", err)
	}
	if got2.RowsProcessed != 42 || got2.InputType != "csv" {
		t.Fatalf("unexpected record: %+v", got2)
	}
	// field omitempty should keep single-value-only field out of CSV records.
	if strings.Contains(lines[1], "\"field\":") {
		t.Fatalf("field should be omitted from csv record: %s", lines[1])
	}
}

func TestNewAuditRecordDefaultsToFailure(t *testing.T) {
	rec := NewAuditRecord()
	if rec.Status != "failure" {
		t.Fatalf("expected default status=failure, got %q", rec.Status)
	}
	if rec.Timestamp == "" {
		t.Fatal("expected non-empty timestamp")
	}
}

func TestWriteAuditLogIsNonFatalOnError(t *testing.T) {
	orig := auditLogPath
	// Force a path that cannot be created — a NUL byte is illegal on every OS.
	auditLogPath = string([]byte{0, 0})
	t.Cleanup(func() { auditLogPath = orig })

	// Suppress the expected "warning: ..." stderr noise during the test.
	origStderr := os.Stderr
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open devnull: %v", err)
	}
	os.Stderr = devNull
	t.Cleanup(func() {
		os.Stderr = origStderr
		devNull.Close()
	})

	// Should NOT panic. The function deliberately swallows write errors as
	// warnings so a failed audit write never blocks an Ops decryption.
	WriteAuditLog(&AuditRecord{Status: "failure"})
}
