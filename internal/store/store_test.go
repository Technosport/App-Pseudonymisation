package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sample() Participant {
	return Participant{Nom: "Dupont", Prenom: "Éloïse", DateNaissance: "12/03/1990", Sexe: "femme", Taille: "165,5", Poids: "60", Email: "e@x.fr", CodeManip: "M1"}
}

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.pdb")
	s, err := Create(p, "motdepasse", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestRoundTripAndPassword(t *testing.T) {
	s, path := newStore(t)
	p, err := s.Add(sample(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ID) != 8 || p.DateNaissance != "1990-03-12" || p.Taille != "165.5" || p.Sexe != "Femme" {
		t.Fatalf("normalisation inattendue: %+v", p)
	}
	raw, _ := os.ReadFile(path)
	if string(raw) == "" || contains(raw, "Dupont") {
		t.Fatal("les données ne sont pas chiffrées")
	}
	if _, err := Open(path, "mauvais"); !errors.Is(err, ErrBadPassword) {
		t.Fatalf("attendu ErrBadPassword, obtenu %v", err)
	}
	s2, err := Open(path, "motdepasse")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s2.Get(p.ID); err != nil || got.Nom != "Dupont" {
		t.Fatalf("lecture: %v %+v", err, got)
	}
}

func contains(b []byte, s string) bool {
	return len(s) > 0 && string(b) != "" && indexOf(string(b), s) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

func TestCorruptedFile(t *testing.T) {
	s, path := newStore(t)
	s.Add(sample(), false)
	raw, _ := os.ReadFile(path)
	raw[len(raw)-1] ^= 0xff
	os.WriteFile(path, raw, 0o600)
	if _, err := Open(path, "motdepasse"); err == nil {
		t.Fatal("un fichier altéré doit être refusé")
	}
}

func TestDuplicates(t *testing.T) {
	s, _ := newStore(t)
	first, _ := s.Add(sample(), false)
	d := sample()
	d.Nom, d.Prenom = "DUPONT ", "eloise"
	_, err := s.Add(d, false)
	var de *DuplicateError
	if !errors.As(err, &de) || de.IDs[0] != first.ID {
		t.Fatalf("doublon non détecté: %v", err)
	}
	if _, err := s.Add(d, true); err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 2 {
		t.Fatal("force doit ajouter")
	}
}

func TestValidation(t *testing.T) {
	bad := []func(*Participant){
		func(p *Participant) { p.Nom = "" },
		func(p *Participant) { p.DateNaissance = "31/02/2000" },
		func(p *Participant) { p.DateNaissance = "01/01/2999" },
		func(p *Participant) { p.Sexe = "?" },
		func(p *Participant) { p.Taille = "abc" },
		func(p *Participant) { p.Poids = "9999" },
		func(p *Participant) { p.Email = "pasunmail" },
	}
	for i, f := range bad {
		p := sample()
		f(&p)
		if _, err := Normalize(p); err == nil {
			t.Errorf("cas %d accepté à tort", i)
		}
	}
}

func TestUpdateDelete(t *testing.T) {
	s, _ := newStore(t)
	p, _ := s.Add(sample(), false)
	q := sample()
	q.Poids = "70"
	u, err := s.Update(p.ID, q, false)
	if err != nil || u.ID != p.ID || u.DateAjout != p.DateAjout || u.Poids != "70" {
		t.Fatalf("update: %v %+v", err, u)
	}
	if err := s.Delete(p.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("suppression double")
	}
	for _, a := range s.Audit(0) {
		if a.Detail != "" && a.Action != "import" {
			t.Fatal("le journal ne doit pas contenir de données personnelles")
		}
	}
}

func TestImport(t *testing.T) {
	s, _ := newStore(t)
	a, b, c := sample(), sample(), sample()
	a.ID = "ABCD1234"
	b.Nom, b.ID = "Autre", "abcd1234" // ID déjà pris après normalisation
	c.Nom = ""
	rep, err := s.Import([]ImportRecord{{3, a}, {4, b}, {5, c}, {6, a}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Added != 2 || rep.NewIDs != 1 || rep.Duplicates != 1 || len(rep.Errors) != 1 {
		t.Fatalf("rapport: %+v", rep)
	}
	if _, err := s.Get("ABCD1234"); err != nil {
		t.Fatal("ID importé non conservé")
	}
}

func TestImportKeepsLegacyRows(t *testing.T) {
	s, _ := newStore(t)
	first, second, noDob, badMail := sample(), sample(), sample(), sample()
	first.ID, second.ID = "AAAA1111", "BBBB2222"
	noDob.Nom, noDob.DateNaissance, noDob.ID = "SansDate", "", "CCCC3333"
	badMail.Nom, badMail.Email, badMail.ID = "Mail", "aa", "DDDD4444"
	recs := []ImportRecord{{1, first}, {2, second}, {3, noDob}, {4, badMail}}
	rep, err := s.Import(recs)
	if err != nil || rep.Added != 4 || rep.SamePerson != 1 || rep.Duplicates != 0 || len(rep.Errors) != 0 {
		t.Fatalf("rapport: %+v %v", rep, err)
	}
	for _, id := range []string{"AAAA1111", "BBBB2222", "CCCC3333", "DDDD4444"} {
		if _, err := s.Get(id); err != nil {
			t.Fatalf("ID %s perdu", id)
		}
	}
	// Réimporter le même fichier ne doit rien ajouter.
	rep, _ = s.Import(recs)
	if rep.Added != 0 || rep.Duplicates != 4 {
		t.Fatalf("réimport: %+v", rep)
	}
}

func TestChangePassword(t *testing.T) {
	s, path := newStore(t)
	s.Add(sample(), false)
	if err := s.ChangePassword("faux", "nouveaumdp1"); !errors.Is(err, ErrBadPassword) {
		t.Fatal("ancien mot de passe non vérifié")
	}
	if err := s.ChangePassword("motdepasse", "court"); err == nil {
		t.Fatal("mot de passe trop court accepté")
	}
	if err := s.ChangePassword("motdepasse", "nouveaumdp1"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, "motdepasse"); err == nil {
		t.Fatal("ancien mot de passe encore valide")
	}
	if s2, err := Open(path, "nouveaumdp1"); err != nil || len(s2.List()) != 1 {
		t.Fatal("réouverture impossible")
	}
}

func TestBackupRotation(t *testing.T) {
	s, _ := newStore(t)
	dir := t.TempDir()
	base := time.Now().AddDate(0, 0, -100)
	for i := 0; i < 60; i++ {
		name := backupPrefix + base.Add(time.Duration(i)*24*time.Hour).Format("20060102_150405") + backupExt
		os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600)
	}
	if _, err := s.Backup(dir); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) < keepRecent || len(entries) > keepRecent+4 {
		t.Fatalf("rotation inattendue: %d fichiers", len(entries))
	}
	newest := backupPrefix + time.Now().Format("20060102_15")
	found := false
	for _, e := range entries {
		if len(e.Name()) >= len(newest) && e.Name()[:len(newest)] == newest {
			found = true
		}
	}
	if !found {
		t.Fatal("la sauvegarde récente a été supprimée")
	}
}

func TestAge(t *testing.T) {
	at := time.Date(2026, 3, 11, 0, 0, 0, 0, time.UTC)
	if Age("1990-03-12", at) != 35 || Age("1990-03-11", at) != 36 {
		t.Fatal("calcul d'âge")
	}
}
