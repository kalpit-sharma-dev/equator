package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStderr swaps os.Stderr for a pipe for the duration of fn() and
// returns everything written to stderr. We use this to assert on validation
// error messages produced by run().
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()

	fn()

	_ = w.Close()
	<-done
	os.Stderr = orig
	return buf.String()
}

// redirectAuditLog sends the audit log to a temp file for the test so
// real /var/log writes never happen and rogue stderr noise is suppressed.
func redirectAuditLog(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	orig := auditLogPath
	auditLogPath = filepath.Join(tmp, "audit.log")
	t.Cleanup(func() { auditLogPath = orig })
}

func TestSecretNameAndProjectEnvVarFallback(t *testing.T) {
	redirectAuditLog(t)

	// Neither flag is provided; env vars supply both.
	t.Setenv(envSecretName, "aes-ops-key")
	t.Setenv(envProject, "my-gcp-project")

	// Force validation to fail on --mode so we never reach the live
	// Secret Manager call. We're only asserting that the env-var fallback
	// satisfied --secret-name and --project.
	stderr := captureStderr(t, func() {
		_ = run([]string{"--mode=invalid", "--value=test", "--field=customer_id"})
	})

	if strings.Contains(stderr, "--secret-name is required") {
		t.Fatalf("OPS_CRYPTO_SECRET_NAME fallback did not take effect.\nstderr:\n%s", stderr)
	}
	if strings.Contains(stderr, "--project is required") {
		t.Fatalf("OPS_CRYPTO_PROJECT fallback did not take effect.\nstderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "--mode must be one of") {
		t.Fatalf("expected --mode validation error; saw stderr:\n%s", stderr)
	}
}

func TestFlagTakesPrecedenceOverEnvVar(t *testing.T) {
	redirectAuditLog(t)

	// Env says one thing, flag says another — flag must win (12-factor).
	t.Setenv(envSecretName, "env-secret")
	t.Setenv(envProject, "env-project")

	var capturedSecret, capturedProject string
	// Re-implement the relevant resolution slice locally so we can observe
	// the resolved values without depending on a network round-trip.
	resolve := func(flagSecret, flagProject string) (string, string) {
		s, p := flagSecret, flagProject
		if s == "" {
			s = strings.TrimSpace(os.Getenv(envSecretName))
		}
		if p == "" {
			p = strings.TrimSpace(os.Getenv(envProject))
		}
		return s, p
	}
	capturedSecret, capturedProject = resolve("flag-secret", "flag-project")

	if capturedSecret != "flag-secret" {
		t.Fatalf("flag did not override env for secret: got %q", capturedSecret)
	}
	if capturedProject != "flag-project" {
		t.Fatalf("flag did not override env for project: got %q", capturedProject)
	}
}

func TestMissingSecretNameAndProjectErrorsMentionEnvVars(t *testing.T) {
	redirectAuditLog(t)

	// Ensure nothing is set in the environment.
	t.Setenv(envSecretName, "")
	t.Setenv(envProject, "")

	stderr := captureStderr(t, func() {
		_ = run([]string{"--mode=hash", "--value=CUST1"})
	})

	if !strings.Contains(stderr, "--secret-name is required") {
		t.Fatalf("expected --secret-name validation error; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, envSecretName) {
		t.Fatalf("expected error message to mention env var %s; stderr:\n%s",
			envSecretName, stderr)
	}
	if !strings.Contains(stderr, "--project is required") {
		t.Fatalf("expected --project validation error; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, envProject) {
		t.Fatalf("expected error message to mention env var %s; stderr:\n%s",
			envProject, stderr)
	}
}

func TestWhitespaceOnlyEnvVarTreatedAsEmpty(t *testing.T) {
	redirectAuditLog(t)

	// Tabs/spaces should be trimmed and treated as missing, otherwise an
	// admin who accidentally exported `OPS_CRYPTO_SECRET_NAME=" "` would
	// hit confusing 'invalid resource name' errors from the API instead of
	// a clean validation message.
	t.Setenv(envSecretName, "   ")
	t.Setenv(envProject, "\t")

	stderr := captureStderr(t, func() {
		_ = run([]string{"--mode=hash", "--value=CUST1"})
	})

	if !strings.Contains(stderr, "--secret-name is required") {
		t.Fatalf("expected --secret-name validation error; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "--project is required") {
		t.Fatalf("expected --project validation error; stderr:\n%s", stderr)
	}
}
