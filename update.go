package main

import (
	"archive/zip"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Clé publique Ed25519 officielle pour valider l'authenticité des mises à jour Technosport.
// Seules les archives signées avec la clé privée correspondante (détenue par le responsable de publication)
// peuvent être installées.
const ReleasePublicKeyHex = "e1eeab2faa408c2308652840e97e429bd09d0141c56ba9d049124801e46523b4"

func verifyZipSignature(zipBytes, sigBytes []byte) error {
	pubBytes, err := hex.DecodeString(ReleasePublicKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("clé publique de vérification invalide dans le binaire")
	}
	// Accepte à la fois la signature brute (64 octets) ou encodée en hexadécimal (128 caractères)
	cleanSig := sigBytes
	if len(cleanSig) != ed25519.SignatureSize {
		if decoded, errDec := hex.DecodeString(strings.TrimSpace(string(cleanSig))); errDec == nil && len(decoded) == ed25519.SignatureSize {
			cleanSig = decoded
		} else {
			return fmt.Errorf("taille de signature invalide (%d octets, attendu %d)", len(sigBytes), ed25519.SignatureSize)
		}
	}
	if !ed25519.Verify(pubBytes, zipBytes, cleanSig) {
		return errors.New("mise à jour rejetée : signature cryptographique Ed25519 invalide ou corrompue")
	}
	return nil
}

var zipVersionRegex = regexp.MustCompile(`(?i)(?:participants|app-pseudonymisation-tks)[-_]v?(\d+\.\d+\.\d+(?:-[\w.]+)?)\.zip$`)

// checkAndApplyZipUpdate cherche un fichier zip de mise à jour dans le dossier parent (racine de la clé)
// ou dans le dossier de l'exécutable, et applique les nouveaux binaires si sa version est plus récente.
func checkAndApplyZipUpdate(appDir string, currentVersion string) {
	candidatesDirs := []string{
		filepath.Dir(appDir), // Racine de la clé USB (parent du dossier app)
		appDir,               // Directement dans le dossier de l'app
		filepath.Join(filepath.Dir(appDir), "Participants"), // Cas de transition d'ancien dossier
	}

	seen := map[string]bool{}
	for _, dir := range candidatesDirs {
		absDir, err := filepath.Abs(dir)
		if err != nil || seen[absDir] {
			continue
		}
		seen[absDir] = true

		entries, err := os.ReadDir(absDir)
		if err != nil {
			continue
		}

		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			matches := zipVersionRegex.FindStringSubmatch(name)
			if len(matches) < 2 {
				continue
			}
			newVer := "v" + strings.TrimPrefix(matches[1], "v")
			currVer := "v" + strings.TrimPrefix(currentVersion, "v")

			// Si nous sommes en mode dev, ou si la version du zip est différente/plus récente
			if currentVersion != "dev" && !isNewerVersion(currVer, newVer) {
				continue
			}

			zipPath := filepath.Join(absDir, name)

			// Vérification de la signature cryptographique Ed25519
			sigPath := zipPath + ".sig"
			if _, err := os.Stat(sigPath); err != nil {
				sigPath = strings.TrimSuffix(zipPath, filepath.Ext(zipPath)) + ".sig"
			}
			sigBytes, err := os.ReadFile(sigPath)
			if err != nil {
				if currentVersion != "dev" {
					fmt.Printf("Mise à jour ignorée pour %s : fichier de signature manquant (.sig requis)\n\n", name)
					continue
				}
			} else {
				zipBytes, errZip := os.ReadFile(zipPath)
				if errZip != nil {
					fmt.Printf("Erreur lecture zip %s : %v\n\n", name, errZip)
					continue
				}
				if errSig := verifyZipSignature(zipBytes, sigBytes); errSig != nil {
					fmt.Printf("SÉCURITÉ : %v pour %s\n\n", errSig, name)
					continue
				}
			}

			fmt.Printf("\n=== Mise à jour authentifiée détectée : %s (version actuelle : %s) ===\n", newVer, currentVersion)
			fmt.Println("Application de la mise à jour en cours...")

			if err := applyZip(zipPath, appDir); err != nil {
				fmt.Printf("Erreur lors de l'application de la mise à jour : %v\n\n", err)
				continue
			}

			// Renomme le zip et la signature pour ne pas les ré-appliquer indéfiniment
			doneName := filepath.Join(absDir, name+".installe")
			_ = os.Rename(zipPath, doneName)
			if sigBytes != nil {
				_ = os.Rename(sigPath, sigPath+".installe")
			}

			fmt.Println("Mise à jour appliquée avec succès !")
			fmt.Println("La réécriture et l'intégrité de l'ensemble des fichiers ont été vérifiées.")
			fmt.Println("Les données (data/ et backups/) ont été intégralement préservées.")
			fmt.Println("Veuillez relancer l'application pour profiter de la nouvelle version.")
			fmt.Println("Appuyez sur Entrée pour quitter...")
			var dummy string
			fmt.Scanln(&dummy)
			os.Exit(0)
		}
	}
}

func isNewerVersion(current, candidate string) bool {
	// Simple comparaison sémantique ou d'inégalité
	c := parseSemver(current)
	n := parseSemver(candidate)
	for i := 0; i < 3; i++ {
		if n[i] > c[i] {
			return true
		}
		if n[i] < c[i] {
			return false
		}
	}
	return false
}

func parseSemver(v string) [3]int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	var res [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		var n int
		fmt.Sscanf(parts[i], "%d", &n)
		res[i] = n
	}
	return res
}

type extractedFileRecord struct {
	zipFile *zip.File
	path    string
}

func applyZip(zipFile, destDir string) error {
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer r.Close()

	installedFiles := make(map[string]bool)
	var records []extractedFileRecord

	for _, f := range r.File {
		// Normalise le chemin relatif dans le zip
		cleanPath := path.Clean(strings.ReplaceAll(f.Name, "\\", "/"))
		if strings.HasPrefix(cleanPath, "..") || strings.Contains(cleanPath, "/../") || path.IsAbs(cleanPath) {
			return fmt.Errorf("archive invalide : tentative d'évasion de répertoire détectée (%s)", f.Name)
		}

		// Souvent le zip contient un sous-dossier racine (ex: App-Pseudonymisation-TKS/...)
		parts := strings.Split(cleanPath, "/")
		if len(parts) > 1 {
			// Retire le premier dossier englobant s'il existe
			parts = parts[1:]
		}
		rel := filepath.Join(parts...)
		if rel == "" || rel == "." {
			continue
		}

		// Ne jamais toucher à data/ ni backups/
		lower := strings.ToLower(rel)
		if strings.HasPrefix(lower, "data") || strings.HasPrefix(lower, "backups") {
			continue
		}

		targetPath := filepath.Join(destDir, rel)

		// Protection Zip Slip : s'assurer que le chemin d'extraction reste confiné dans destDir
		cleanDest := filepath.Clean(destDir)
		cleanTarget := filepath.Clean(targetPath)
		if !strings.HasPrefix(cleanTarget, cleanDest+string(filepath.Separator)) && cleanTarget != cleanDest {
			return fmt.Errorf("archive invalide : tentative d'évasion de répertoire détectée (%s)", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return err
			}
			continue
		}

		if err := extractFile(f, targetPath); err != nil {
			return err
		}
		installedFiles[strings.ToLower(cleanTarget)] = true
		records = append(records, extractedFileRecord{
			zipFile: f,
			path:    cleanTarget,
		})
	}

	if len(records) == 0 {
		return errors.New("mise à jour échouée : aucun fichier valide trouvé dans l'archive")
	}

	// Contrôle d'intégrité strict post-réécriture : vérifie la taille et le CRC32 de chaque fichier relu depuis le disque
	for _, rec := range records {
		if err := verifyWrittenFile(rec.zipFile, rec.path); err != nil {
			return fmt.Errorf("échec de vérification après réécriture : %w", err)
		}
	}

	// Nettoyage intelligent : supprime les anciens fichiers applicatifs obsolètes qui ne sont plus dans le zip
	cleanupObsoleteFiles(destDir, installedFiles)

	// Re-vérification post-nettoyage pour s'assurer qu'aucun fichier légitime n'a été altéré
	for _, rec := range records {
		if err := verifyWrittenFile(rec.zipFile, rec.path); err != nil {
			return fmt.Errorf("échec de validation finale des fichiers : %w", err)
		}
	}

	return nil
}

func cleanupObsoleteFiles(destDir string, keepFiles map[string]bool) {
	entries, err := os.ReadDir(destDir)
	if err != nil {
		return
	}

	for _, e := range entries {
		name := e.Name()
		fullPath := filepath.Clean(filepath.Join(destDir, name))

		// Règle 1 : Ne JAMAIS toucher aux dossiers
		if e.IsDir() {
			continue
		}

		// Règle 2 : Ne pas toucher aux fichiers qui viennent d'être installés par la mise à jour
		if keepFiles[strings.ToLower(fullPath)] {
			continue
		}

		// Règle 3 : Ne jamais toucher aux fichiers de verrou ou de données
		lower := strings.ToLower(name)
		if lower == ".instance" || strings.HasSuffix(lower, ".pdb") {
			continue
		}

		// Règle 4 : Ne jamais toucher aux documents personnels de l'utilisateur (.xlsx, .csv, .pdf...)
		if strings.HasSuffix(lower, ".xlsx") || strings.HasSuffix(lower, ".csv") || strings.HasSuffix(lower, ".pdf") {
			continue
		}

		// Règle 5 : Supprimer les anciens fichiers applicatifs (.exe, .command, binaires mac, docs obsolètes, fichiers résiduels)
		isAppFile := strings.HasSuffix(lower, ".exe") ||
			strings.HasSuffix(lower, ".command") ||
			strings.HasSuffix(lower, ".old") ||
			strings.HasSuffix(lower, ".tmp") ||
			strings.HasSuffix(lower, ".txt") ||
			strings.Contains(lower, "participants-mac") ||
			strings.Contains(lower, "pseudonymisation-mac")

		if isAppFile {
			if err := os.Remove(fullPath); err != nil {
				// Sous Windows, si le binaire en cours d'exécution ne peut pas être supprimé directement,
				// on le renomme en .old (s'il ne l'est pas déjà) pour qu'il ne parasite plus le dossier
				if !strings.HasSuffix(lower, ".old") {
					_ = os.Rename(fullPath, fmt.Sprintf("%s.%d.old", fullPath, time.Now().UnixNano()))
				}
			}
		}
	}
}

func extractFile(f *zip.File, target string) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}

	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	// Sur Windows, si l'exécutable actuel porte le même nom, on écrit dans un .tmp
	// puis on remplace.
	tmp := fmt.Sprintf("%s.%d.tmp", target, time.Now().UnixNano())
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	// Vidage forcé sur le support de stockage (clé USB / cache OS)
	_ = out.Sync()
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}

	// Tente le remplacement atomique
	if err := os.Rename(tmp, target); err != nil {
		// Sous Windows, si le fichier cible est en cours d'exécution, on déplace d'abord l'existant
		old := fmt.Sprintf("%s.%d.old", target, time.Now().UnixNano())
		if errRename := os.Rename(target, old); errRename == nil {
			if err2 := os.Rename(tmp, target); err2 == nil {
				_ = os.Chmod(target, f.Mode())
				return nil
			}
			// Rollback si le nouveau fichier ne peut être mis en place
			_ = os.Rename(old, target)
		}
		os.Remove(tmp)
		return fmt.Errorf("impossible de remplacer le fichier cible %s : %w", filepath.Base(target), err)
	}
	_ = os.Chmod(target, f.Mode())
	return nil
}

func verifyWrittenFile(f *zip.File, targetPath string) error {
	fi, err := os.Stat(targetPath)
	if err != nil {
		return fmt.Errorf("fichier introuvable après réécriture (%s) : %w", filepath.Base(targetPath), err)
	}
	if uint64(fi.Size()) != f.UncompressedSize64 {
		return fmt.Errorf("taille incorrecte après réécriture pour %s (%d octets attendus, %d constatés)",
			filepath.Base(targetPath), f.UncompressedSize64, fi.Size())
	}

	file, err := os.Open(targetPath)
	if err != nil {
		return fmt.Errorf("impossible de relire le fichier réécrit (%s) : %w", filepath.Base(targetPath), err)
	}
	defer file.Close()

	hasher := crc32.NewIEEE()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("erreur de lecture de contrôle pour %s : %w", filepath.Base(targetPath), err)
	}
	if hasher.Sum32() != f.CRC32 {
		return fmt.Errorf("somme de contrôle CRC32 invalide après réécriture pour %s (archive: %08x, disque: %08x)",
			filepath.Base(targetPath), f.CRC32, hasher.Sum32())
	}
	return nil
}

type ReleaseInfo struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func CheckRemoteUpdate(currentVersion string) (*ReleaseInfo, error) {
	client := http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/Technosport/App-Pseudonymisation/releases/latest", nil)
	if err == nil {
		req.Header.Set("User-Agent", "App-Pseudonymisation-TKS/"+currentVersion)
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		resp, errDo := client.Do(req)
		if errDo == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			var release ReleaseInfo
			if errJson := json.NewDecoder(resp.Body).Decode(&release); errJson == nil {
				newVer := "v" + strings.TrimPrefix(release.TagName, "v")
				currVer := "v" + strings.TrimPrefix(currentVersion, "v")
				if currentVersion != "dev" && !isNewerVersion(currVer, newVer) {
					return nil, nil // Déjà à jour
				}
				return &release, nil
			}
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	// Fallback résilient sans quota d'API (utilise la redirection web HTTP 302 de GitHub /releases/latest)
	return checkRemoteUpdateWebFallback(currentVersion)
}

func checkRemoteUpdateWebFallback(currentVersion string) (*ReleaseInfo, error) {
	webClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest("GET", "https://github.com/Technosport/App-Pseudonymisation/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := webClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 301 || resp.StatusCode == 302 {
		loc := resp.Header.Get("Location")
		parts := strings.Split(strings.TrimRight(loc, "/"), "/")
		if len(parts) > 0 {
			tag := parts[len(parts)-1]
			if strings.HasPrefix(tag, "v") {
				newVer := tag
				currVer := "v" + strings.TrimPrefix(currentVersion, "v")
				if currentVersion != "dev" && !isNewerVersion(currVer, newVer) {
					return nil, nil
				}
				zipURL := fmt.Sprintf("https://github.com/Technosport/App-Pseudonymisation/releases/download/%s/App-Pseudonymisation-TKS-%s.zip", tag, tag)
				return &ReleaseInfo{
					TagName: tag,
					Body:    "Nouvelle version disponible.",
					Assets: []struct {
						Name               string `json:"name"`
						BrowserDownloadURL string `json:"browser_download_url"`
					}{
						{
							Name:               fmt.Sprintf("App-Pseudonymisation-TKS-%s.zip", tag),
							BrowserDownloadURL: zipURL,
						},
					},
				}, nil
			}
		}
	}
	return nil, nil
}

type ProgressWriter struct {
	Total      int64
	Downloaded int64
	OnProgress func(downloaded, total int64)
}

func (pw *ProgressWriter) Write(p []byte) (int, error) {
	n := len(p)
	pw.Downloaded += int64(n)
	if pw.OnProgress != nil {
		pw.OnProgress(pw.Downloaded, pw.Total)
	}
	return n, nil
}

func downloadSignature(client *http.Client, zipURL string) ([]byte, error) {
	urls := []string{zipURL + ".sig"}
	if strings.HasSuffix(strings.ToLower(zipURL), ".zip") {
		urls = append(urls, strings.TrimSuffix(zipURL, filepath.Ext(zipURL))+".sig")
	}
	for _, u := range urls {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			continue
		}
		sig, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if err == nil && len(sig) > 0 {
			return sig, nil
		}
	}
	return nil, errors.New("signature cryptographique (.sig) introuvable sur GitHub Releases")
}

func ApplyRemoteUpdate(appDir string, downloadURL string, onProgress func(step string, pct int)) error {
	if onProgress != nil {
		onProgress("download", 0)
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("téléchargement échoué, statut: %d", resp.StatusCode)
	}

	const maxZipSize = int64(100 << 20) // 100 Mo max (protection DoS / OOM)
	if resp.ContentLength > maxZipSize {
		return fmt.Errorf("archive trop volumineuse (%d octets, max 100 Mo)", resp.ContentLength)
	}

	tmpFile := filepath.Join(os.TempDir(), "pseudonymisation-update.zip")
	out, err := os.Create(tmpFile)
	if err != nil {
		return err
	}

	total := resp.ContentLength
	pw := &ProgressWriter{
		Total: total,
		OnProgress: func(down, tot int64) {
			if onProgress != nil {
				pct := 0
				if tot > 0 {
					pct = int((down * 100) / tot)
					if pct > 90 {
						pct = 90
					}
				}
				onProgress("download", pct)
			}
		},
	}

	limitBody := io.LimitReader(resp.Body, maxZipSize)
	if _, err := io.Copy(out, io.TeeReader(limitBody, pw)); err != nil {
		out.Close()
		os.Remove(tmpFile)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmpFile)
		return err
	}
	defer os.Remove(tmpFile)

	// Téléchargement et vérification obligatoire de la signature Ed25519
	if onProgress != nil {
		onProgress("verify", 92)
	}
	sigBytes, err := downloadSignature(client, downloadURL)
	if err != nil {
		return fmt.Errorf("sécurité : %w", err)
	}

	zipBytes, err := os.ReadFile(tmpFile)
	if err != nil {
		return fmt.Errorf("lecture archive impossible : %w", err)
	}

	if err := verifyZipSignature(zipBytes, sigBytes); err != nil {
		return fmt.Errorf("sécurité : %w", err)
	}

	if onProgress != nil {
		onProgress("install", 94)
	}
	err = applyZip(tmpFile, appDir)
	if err != nil {
		return fmt.Errorf("échec installation/réécriture : %w", err)
	}

	if onProgress != nil {
		onProgress("verify_files", 98)
		onProgress("done", 100)
	}
	return nil
}

func CleanupOldFiles(appDir string) {
	entries, err := os.ReadDir(appDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".old") {
			_ = os.Remove(filepath.Join(appDir, e.Name()))
		}
	}
}
