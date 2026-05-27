package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

// auditLogPath is the on-disk location of the JSON-lines audit log.
// It is intentionally a var (not a const) so tests can redirect writes to a
// temp file without touching the production path. The production value must
// not be changed.
var auditLogPath = "/var/log/ops-crypto-util/audit.log"

// AuditRecord is one line in the audit log. Every CLI invocation produces
// exactly one record describing who ran what, where, when, and how it ended.
//
// PII discipline: this struct must NEVER contain plaintext values, ciphertext
// values, or any portion of the AES key. Auditors care about who/when/what
// happened, not what data flowed through.
type AuditRecord struct {
	Timestamp     string `json:"timestamp"`
	User          string `json:"user"`
	Hostname      string `json:"hostname"`
	Mode          string `json:"mode"`
	InputType     string `json:"input_type"`
	Field         string `json:"field,omitempty"`
	RowsProcessed int    `json:"rows_processed,omitempty"`
	SecretName    string `json:"secret_name"`
	SecretVersion string `json:"secret_version,omitempty"`
	Project       string `json:"project"`
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
}

// NewAuditRecord seeds an audit record with the values we always know up
// front: timestamp (UTC, RFC3339), OS user, hostname. Status defaults to
// "failure" so that any early panic or os.Exit path still records a failed
// run rather than silently dropping it.
func NewAuditRecord() *AuditRecord {
	rec := &AuditRecord{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    "failure",
		User:      "unknown",
		Hostname:  "unknown",
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		rec.User = u.Username
	}
	if hn, err := os.Hostname(); err == nil && hn != "" {
		rec.Hostname = hn
	}
	return rec
}

// WriteAuditLog appends one JSON line to auditLogPath. It never aborts the
// operation: any failure (missing directory, no permissions, full disk,
// marshal error) is downgraded to a single stderr warning so a failed audit
// write never blocks Ops from decrypting customer data during an incident.
func WriteAuditLog(rec *AuditRecord) {
	line, err := json.Marshal(rec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to marshal audit record: %v\n", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(auditLogPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to create audit log directory %q: %v\n", filepath.Dir(auditLogPath), err)
		return
	}
	// Append-only, group-readable, owner-writable. We never truncate the
	// audit log from within the CLI — rotation is left to logrotate(8).
	f, err := os.OpenFile(auditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to open audit log %q: %v\n", auditLogPath, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write audit log: %v\n", err)
		return
	}
}
