package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	backupPrefix = "participants_"
	backupExt    = ".pdb"
	keepRecent   = 30
)

// Backup copie le fichier chiffré (toujours cohérent grâce à l'écriture atomique)
// puis applique la rotation. Retourne le chemin de la copie.
func (s *Store) Backup(dir string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	blob, err := os.ReadFile(s.path)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := backupPrefix + time.Now().Format("20060102_150405") + backupExt
	dst := filepath.Join(dir, name)
	if err := writeAtomic(dst, blob); err != nil {
		return "", err
	}
	return dst, Rotate(dir, time.Now())
}

func backupTime(name string) (time.Time, bool) {
	if !strings.HasPrefix(name, backupPrefix) || !strings.HasSuffix(name, backupExt) {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("20060102_150405", strings.TrimSuffix(strings.TrimPrefix(name, backupPrefix), backupExt), time.Local)
	return t, err == nil
}

// Rotate conserve les 30 sauvegardes les plus récentes et la plus récente de chaque mois.
func Rotate(dir string, _ time.Time) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type item struct {
		name string
		t    time.Time
	}
	var items []item
	for _, e := range entries {
		if t, ok := backupTime(e.Name()); ok && !e.IsDir() {
			items = append(items, item{e.Name(), t})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].t.After(items[j].t) })
	months := map[string]bool{}
	for i, it := range items {
		m := it.t.Format("2006-01")
		keep := i < keepRecent
		if !months[m] {
			months[m] = true
			keep = true
		}
		if !keep {
			if err := os.Remove(filepath.Join(dir, it.name)); err != nil {
				return fmt.Errorf("rotation des sauvegardes : %w", err)
			}
		}
	}
	return nil
}
