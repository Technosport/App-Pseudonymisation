package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var zipVersionRegex = regexp.MustCompile(`(?i)(?:participants|app-pseudonymisation-tks)[-_]v?(\d+\.\d+\.\d+(?:-[\w.]+)?)\.zip$`)

// checkAndApplyZipUpdate cherche un fichier zip de mise à jour dans le dossier parent (racine de la clé)
// ou dans le dossier de l'exécutable, et applique les nouveaux binaires si sa version est plus récente.
func checkAndApplyZipUpdate(appDir string, currentVersion string) {
	candidatesDirs := []string{
		filepath.Dir(appDir),                    // Racine de la clé USB (parent du dossier app)
		appDir,                                   // Directement dans le dossier de l'app
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
			fmt.Printf("\n=== Mise à jour détectée : %s (version actuelle : %s) ===\n", newVer, currentVersion)
			fmt.Println("Application de la mise à jour en cours...")

			if err := applyZip(zipPath, appDir); err != nil {
				fmt.Printf("Erreur lors de l'application de la mise à jour : %v\n\n", err)
				continue
			}

			// Renomme le zip pour ne pas le ré-appliquer indéfiniment
			doneName := filepath.Join(absDir, name+".installe")
			_ = os.Rename(zipPath, doneName)

			fmt.Println("Mise à jour appliquée avec succès !")
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

func applyZip(zipFile, destDir string) error {
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// Normalise le chemin relatif dans le zip
		// Souvent le zip contient un sous-dossier racine (ex: Participants/App-Pseudonymisation-TKS.exe)
		cleanPath := path.Clean(strings.ReplaceAll(f.Name, "\\", "/"))
		parts := strings.Split(cleanPath, "/")
		if len(parts) > 1 {
			// Retire le premier dossier englobant s'il existe (ex: Participants/...)
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
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return err
			}
			continue
		}

		if err := extractFile(f, targetPath); err != nil {
			return err
		}
	}
	return nil
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

	// Sur Windows, si l'exécutable actuel porte le même nom, on écrit dans un .new
	// mais ici l'application qui tourne est l'ancienne, elle peut s'écraser si c'est un autre nom,
	// ou via un fichier temporaire
	tmp := target + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}

	// Tente le remplacement atomique
	if err := os.Rename(tmp, target); err != nil {
		// Sous Windows, si le fichier cible est en cours d'exécution, renommer l'existant d'abord
		old := target + ".old"
		_ = os.Remove(old)
		if errRename := os.Rename(target, old); errRename == nil {
			if err2 := os.Rename(tmp, target); err2 == nil {
				return nil
			}
		}
		os.Remove(tmp)
		return err
	}
	return nil
}
