package main

import (
	"encoding/json"
	"os"
	"testing"
)

func writeJSON(t *testing.T, data any, filepath string) {
	t.Helper()
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath, jsonData, 0o600); err != nil {
		t.Fatal(err)
	}
}
