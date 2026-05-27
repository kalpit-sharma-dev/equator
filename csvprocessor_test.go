package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProcessCSVRoundTripWithMarkerID(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)
	dir := t.TempDir()

	plainPath := filepath.Join(dir, "plain.csv")
	plain := strings.Join([]string{
		"customer_id,account_number,request,response,extra",
		"CUST1,ACC100,req1,resp1,keep1",
		"CUST2,ACC200,req2,resp2,keep2",
		"CUST3,,,resp3,keep3", // partially empty cells must round-trip cleanly
	}, "\n") + "\n"
	if err := os.WriteFile(plainPath, []byte(plain), 0o600); err != nil {
		t.Fatal(err)
	}

	encPath := filepath.Join(dir, "encrypted.csv")
	rows, err := ProcessCSV(key, plainPath, encPath, "encrypt")
	if err != nil {
		t.Fatalf("encrypt csv: %v", err)
	}
	if rows != 3 {
		t.Fatalf("expected 3 rows, got %d", rows)
	}

	encBytes, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	encReader := csv.NewReader(bytes.NewReader(encBytes))
	encReader.FieldsPerRecord = -1
	encAll, err := encReader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}

	wantHeader := []string{"customer_id", "account_number", "request", "response", "extra", "marker_id"}
	if !equalStringSlices(encAll[0], wantHeader) {
		t.Fatalf("encrypted header: got %v want %v", encAll[0], wantHeader)
	}

	// Every customer_id cell should be replaced with non-empty ciphertext,
	// and marker_id should equal SHA256 of the original customer_id.
	originals := []string{"CUST1", "CUST2", "CUST3"}
	for i, orig := range originals {
		row := encAll[i+1]
		if row[0] == orig {
			t.Fatalf("row %d customer_id not encrypted: %q", i+1, row[0])
		}
		if row[5] != HashSHA256(orig) {
			t.Fatalf("row %d marker_id mismatch: got %q want %q", i+1, row[5], HashSHA256(orig))
		}
		if row[4] != "keep"+string(rune('1'+i)) {
			t.Fatalf("row %d extra column mutated: %q", i+1, row[4])
		}
	}

	// row 3 had empty account_number and request — those cells must remain
	// empty in the encrypted CSV (not encrypted-empty-string ciphertext).
	if encAll[3][1] != "" || encAll[3][2] != "" {
		t.Fatalf("empty cells should pass through unchanged, got %q and %q",
			encAll[3][1], encAll[3][2])
	}

	decPath := filepath.Join(dir, "decrypted.csv")
	rows, err = ProcessCSV(key, encPath, decPath, "decrypt")
	if err != nil {
		t.Fatalf("decrypt csv: %v", err)
	}
	if rows != 3 {
		t.Fatalf("expected 3 rows, got %d", rows)
	}

	decBytes, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatal(err)
	}
	decReader := csv.NewReader(bytes.NewReader(decBytes))
	decReader.FieldsPerRecord = -1
	decAll, err := decReader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}

	// Decrypted four target columns must match the originals; the
	// marker_id column passes through untouched.
	expected := [][]string{
		{"CUST1", "ACC100", "req1", "resp1"},
		{"CUST2", "ACC200", "req2", "resp2"},
		{"CUST3", "", "", "resp3"},
	}
	for i, exp := range expected {
		row := decAll[i+1]
		for j, val := range exp {
			if row[j] != val {
				t.Fatalf("row %d col %d: got %q want %q", i+1, j, row[j], val)
			}
		}
	}
}

func TestVerifyOutputCSVCatchesTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.csv")
	contents := "a,b,c\n1,2,3\n4,5,6\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	// Expected 3 rows but file only has 2 — must fail.
	err := verifyOutputCSV(path, 3, []string{"a", "b", "c"})
	if err == nil {
		t.Fatal("expected verification failure for short output")
	}
	if !strings.Contains(err.Error(), "Output verification failed") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestVerifyOutputCSVCatchesHeaderMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.csv")
	if err := os.WriteFile(path, []byte("x,y,z\n1,2,3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := verifyOutputCSV(path, 1, []string{"a", "b", "c"})
	if err == nil {
		t.Fatal("expected verification failure for mismatched header")
	}
}
