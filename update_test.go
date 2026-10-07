package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		curr, cand string
		want       bool
	}{
		{"v0.1.1", "v0.1.2", true},
		{"v0.1.1", "v0.2.0", true},
		{"v0.1.1", "v1.0.0", true},
		{"v0.1.2", "v0.1.1", false},
		{"v0.1.1", "v0.1.1", false},
		{"0.1.1", "0.1.2", true},
	}
	for _, tc := range tests {
		if got := isNewerVersion(tc.curr, tc.cand); got != tc.want {
			t.Errorf("isNewerVersion(%q, %q) = %v; want %v", tc.curr, tc.cand, got, tc.want)
		}
	}
}

func TestApplyZipPreservesData(t *testing.T) {
	tmpDir := t.TempDir()
	appDir := filepath.Join(tmpDir, "Participants")
	if err := os.MkdirAll(filepath.Join(appDir, "data"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Simule une base existante
	dbPath := filepath.Join(appDir, "data", "participants.pdb")
	if err := os.WriteFile(dbPath, []byte("SECRET_DATA"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Crée un zip de test
	zipPath := filepath.Join(tmpDir, "App-Pseudonymisation-TKS-v0.1.2.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)

	// Fichier dans le zip
	f1, err := zw.Create("Participants/App-Pseudonymisation-TKS.exe")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f1.Write([]byte("NEW_EXE"))

	// Tente d'écraser la base dans le zip (doit être ignoré)
	f2, err := zw.Create("Participants/data/participants.pdb")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f2.Write([]byte("OVERWRITE_ATTEMPT"))

	zw.Close()
	zf.Close()

	if err := applyZip(zipPath, appDir); err != nil {
		t.Fatalf("applyZip failed: %v", err)
	}

	// Vérifie que le nouvel exécutable est là
	newExe, err := os.ReadFile(filepath.Join(appDir, "App-Pseudonymisation-TKS.exe"))
	if err != nil || string(newExe) != "NEW_EXE" {
		t.Fatalf("exe not updated: %v, content=%s", err, string(newExe))
	}

	// Vérifie que la base est intacte
	dbContent, err := os.ReadFile(dbPath)
	if err != nil || string(dbContent) != "SECRET_DATA" {
		t.Fatalf("database was corrupted or overwritten: %v, content=%s", err, string(dbContent))
	}
}
