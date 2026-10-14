package main

import (
	"archive/zip"
	"crypto/ed25519"
	"encoding/hex"
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

	// Fichier dans le zip (dossier App-Pseudonymisation-TKS)
	f1, err := zw.Create("App-Pseudonymisation-TKS/App-Pseudonymisation-TKS.exe")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f1.Write([]byte("NEW_EXE"))

	// Tente d'écraser la base dans le zip (doit être ignoré)
	f2, err := zw.Create("App-Pseudonymisation-TKS/data/participants.pdb")
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

func TestApplyZipCleansObsoleteFiles(t *testing.T) {
	tmpDir := t.TempDir()
	appDir := filepath.Join(tmpDir, "App-Pseudonymisation-TKS")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Ancien fichier à nettoyer
	oldExe := filepath.Join(appDir, "Participants.exe")
	if err := os.WriteFile(oldExe, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldDoc := filepath.Join(appDir, "LISEZMOI.txt")
	if err := os.WriteFile(oldDoc, []byte("OLD"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Document personnel de l'utilisateur à NE PAS nettoyer
	userDoc := filepath.Join(appDir, "export.xlsx")
	if err := os.WriteFile(userDoc, []byte("USER_DATA"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Nouveau zip contenant App-Pseudonymisation-TKS.exe et README.txt
	zipPath := filepath.Join(tmpDir, "App-Pseudonymisation-TKS-v0.1.4.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)

	f1, _ := zw.Create("App-Pseudonymisation-TKS/App-Pseudonymisation-TKS.exe")
	_, _ = f1.Write([]byte("NEW_EXE"))
	f2, _ := zw.Create("App-Pseudonymisation-TKS/README.txt")
	_, _ = f2.Write([]byte("NEW_DOC"))

	zw.Close()
	zf.Close()

	if err := applyZip(zipPath, appDir); err != nil {
		t.Fatalf("applyZip failed: %v", err)
	}

	// Les anciens fichiers applicatifs doivent avoir été supprimés
	if _, err := os.Stat(oldExe); !os.IsNotExist(err) {
		t.Errorf("expected %s to be deleted, err=%v", oldExe, err)
	}
	if _, err := os.Stat(oldDoc); !os.IsNotExist(err) {
		t.Errorf("expected %s to be deleted, err=%v", oldDoc, err)
	}

	// Le fichier personnel de l'utilisateur doit être resté intact
	if content, err := os.ReadFile(userDoc); err != nil || string(content) != "USER_DATA" {
		t.Errorf("user personal file should be preserved, got err=%v", err)
	}
}

func TestVerifyZipSignature(t *testing.T) {
	// Clé privée correspondant à ReleasePublicKeyHex (utilisée uniquement pour le test unitaire)
	privHex := "ed75ac1bc6e62c19d038ba820c527f72651872adbfd9a685abf265292b72ce8e2b0ce5c1a0083d2cc6b5a92c5915aea284f60373208d445ca15dacf901974067"
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("TEST_ZIP_ARCHIVE_CONTENT_12345")
	validSig := ed25519.Sign(privBytes, payload)

	// Cas 1 : Signature brute valide
	if err := verifyZipSignature(payload, validSig); err != nil {
		t.Fatalf("échec vérification signature brute valide : %v", err)
	}

	// Cas 2 : Signature hexadécimale valide
	sigHex := []byte(hex.EncodeToString(validSig))
	if err := verifyZipSignature(payload, sigHex); err != nil {
		t.Fatalf("échec vérification signature hexadécimale valide : %v", err)
	}

	// Cas 3 : Archive altérée / corrompue
	tamperedPayload := []byte("TEST_ZIP_ARCHIVE_CONTENT_TAMPERED")
	if err := verifyZipSignature(tamperedPayload, validSig); err == nil {
		t.Fatal("sécurité compromise : l'archive altérée a été acceptée !")
	}

	// Cas 4 : Mauvaise signature
	badSig := make([]byte, 64)
	copy(badSig, validSig)
	badSig[0] ^= 0xFF
	if err := verifyZipSignature(payload, badSig); err == nil {
		t.Fatal("sécurité compromise : la fausse signature a été acceptée !")
	}
}

func TestApplyZipSlipProtection(t *testing.T) {
	tmpDir := t.TempDir()
	appDir := filepath.Join(tmpDir, "App")
	_ = os.MkdirAll(appDir, 0o755)

	zipPath := filepath.Join(tmpDir, "slip.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)

	// Tentative de Zip Slip (traversée de répertoire)
	f, err := zw.Create("App/../../escape.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("MALICIOUS"))
	zw.Close()
	zf.Close()

	err = applyZip(zipPath, appDir)
	if err == nil {
		t.Fatal("sécurité compromise : le Zip Slip n'a pas été détecté !")
	}
}
