package main

import (
	"archive/zip"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
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
	payload := []byte("TEST_ZIP_ARCHIVE_CONTENT_12345")
	// Signature Ed25519 pré-calculée pour payload avec la clé correspondant à ReleasePublicKeyHex
	const validSigHex = "e64af75709afdb5510e88b2cd454607ed5f78393671ae73cbce3e0a6a2ffef23f0718e30a3ba29a74a251870e1ca798e62c202f0717876b6d9dcf70d6515eb0b"
	validSig, err := hex.DecodeString(validSigHex)
	if err != nil {
		t.Fatal(err)
	}

	// Cas 1 : Signature brute valide
	if err := verifyZipSignature(payload, validSig); err != nil {
		t.Fatalf("échec vérification signature brute valide : %v", err)
	}

	// Cas 2 : Signature hexadécimale valide
	if err := verifyZipSignature(payload, []byte(validSigHex)); err != nil {
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

func TestVerifyWrittenFileIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	appDir := filepath.Join(tmpDir, "App")
	_ = os.MkdirAll(appDir, 0o755)

	// Création d'un zip avec un fichier
	zipPath := filepath.Join(tmpDir, "test.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	expectedContent := []byte("VALID_BIN_CONTENT_XYZ")
	w, err := zw.Create("App-Pseudonymisation-TKS/App.exe")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(expectedContent)
	zw.Close()
	zf.Close()

	// Ouvrir le zip pour obtenir l'objet *zip.File
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	zipFileEntry := r.File[0]
	targetPath := filepath.Join(appDir, "App.exe")

	// 1. Fichier non encore présent sur le disque : doit échouer
	if err := verifyWrittenFile(zipFileEntry, targetPath); err == nil {
		t.Fatal("la vérification aurait dû échouer car le fichier est absent du disque")
	}

	// 2. Écrire le fichier avec le contenu attendu : doit réussir
	if err := os.WriteFile(targetPath, expectedContent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyWrittenFile(zipFileEntry, targetPath); err != nil {
		t.Fatalf("la vérification du fichier valide a échoué : %v", err)
	}

	// 3. Fichier présent mais altéré (même taille mais contenu différent -> CRC32 différent)
	corruptedSameSize := []byte("WALID_BIN_CONTENT_XYZ")
	if err := os.WriteFile(targetPath, corruptedSameSize, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyWrittenFile(zipFileEntry, targetPath); err == nil {
		t.Fatal("la vérification aurait dû échouer suite à un CRC32 non conforme")
	}

	// 4. Fichier tronqué (taille différente)
	truncated := []byte("SHORT")
	if err := os.WriteFile(targetPath, truncated, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyWrittenFile(zipFileEntry, targetPath); err == nil {
		t.Fatal("la vérification aurait dû échouer suite à une taille non conforme")
	}
}

func TestApplyZipFailsOnEmptyArchive(t *testing.T) {
	tmpDir := t.TempDir()
	appDir := filepath.Join(tmpDir, "App")
	_ = os.MkdirAll(appDir, 0o755)

	zipPath := filepath.Join(tmpDir, "empty.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)
	zw.Close()
	zf.Close()

	if err := applyZip(zipPath, appDir); err == nil {
		t.Fatal("applyZip aurait dû échouer sur une archive sans aucun fichier")
	}
}

func TestApplyZipMultiFilesVerification(t *testing.T) {
	tmpDir := t.TempDir()
	appDir := filepath.Join(tmpDir, "App")
	_ = os.MkdirAll(appDir, 0o755)

	zipPath := filepath.Join(tmpDir, "full_release.zip")
	zf, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(zf)

	files := map[string]string{
		"App-Pseudonymisation-TKS/App-Pseudonymisation-TKS.exe":       "EXE_BIN_DATA_V2",
		"App-Pseudonymisation-TKS/App-Pseudonymisation-TKS-mac-arm64": "MAC_ARM_BIN",
		"App-Pseudonymisation-TKS/Lancer-Mac.command":                 "#!/bin/bash\necho ok",
		"App-Pseudonymisation-TKS/README.txt":                         "Instructions v2",
	}

	for p, content := range files {
		w, err := zw.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	zw.Close()
	zf.Close()

	if err := applyZip(zipPath, appDir); err != nil {
		t.Fatalf("applyZip failed on valid archive: %v", err)
	}

	// Vérifie que chaque fichier est bien présent et a le contenu exact
	for p, expected := range files {
		clean := strings.TrimPrefix(p, "App-Pseudonymisation-TKS/")
		target := filepath.Join(appDir, clean)
		got, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("fichier réécrit manquant (%s): %v", clean, err)
		}
		if string(got) != expected {
			t.Fatalf("contenu incorrect pour %s: attendu %q, reçu %q", clean, expected, string(got))
		}
	}
}
