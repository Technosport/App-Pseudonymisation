package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

func setupTestAdminKey(t *testing.T) (formatted string, rawHex string) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prev := AdminPublicKeyHex
	AdminPublicKeyHex = hex.EncodeToString(priv.PublicKey().Bytes())
	t.Cleanup(func() { AdminPublicKeyHex = prev })
	rawHex = hex.EncodeToString(priv.Bytes())
	formatted = "TKSR-" + rawHex
	return formatted, rawHex
}

func TestAdminRecovery(t *testing.T) {
	validKeyFormatted, validKeyRaw := setupTestAdminKey(t)
	s, path := newStore(t)
	p, err := s.Add(sample(), false)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := "TKSR-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000"

	// 1. Wrong key fails
	if _, err := OpenAdmin(path, wrongKey); err == nil {
		t.Fatal("ouverture admin avec mauvaise clé acceptée à tort")
	}

	// 2. Open with formatted key
	sAdmin, err := OpenAdmin(path, validKeyFormatted)
	if err != nil {
		t.Fatalf("OpenAdmin échoué: %v", err)
	}
	if !sAdmin.IsAdmin() {
		t.Fatal("IsAdmin doit être vrai")
	}
	got, err := sAdmin.Get(p.ID)
	if err != nil || got.Nom != "Dupont" {
		t.Fatalf("participant non lu via admin: %v %+v", err, got)
	}

	// 3. Open with raw hex key
	sAdmin2, err := OpenAdmin(path, validKeyRaw)
	if err != nil {
		t.Fatalf("OpenAdmin raw échoué: %v", err)
	}
	if !sAdmin2.IsAdmin() {
		t.Fatal("IsAdmin doit être vrai")
	}

	// 4. Reset password as admin
	if err := sAdmin.ResetPassword("nouveaumdp_chercheur"); err != nil {
		t.Fatalf("ResetPassword échoué: %v", err)
	}

	// 5. Normal user opens with new password
	sUserNew, err := Open(path, "nouveaumdp_chercheur")
	if err != nil {
		t.Fatalf("Open avec nouveau mdp réinitialisé échoué: %v", err)
	}
	if sUserNew.IsAdmin() {
		t.Fatal("IsAdmin doit être faux pour user")
	}
	if len(sUserNew.List()) != 1 {
		t.Fatal("participants perdus après réinitialisation")
	}

	// 6. Old user password no longer works
	if _, err := Open(path, "motdepasse"); err == nil {
		t.Fatal("ancien mot de passe utilisateur encore valide")
	}
}

func TestV1MigrationToV2(t *testing.T) {
	validKeyFormatted, _ := setupTestAdminKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.pdb")
	pw := "legacy_password"

	// 1. Manually craft a genuine V1 file
	h := headerV1{Time: 3, Mem: 64 * 1024, Threads: 4}
	rand.Read(h.Salt[:])
	key := deriveKey(pw, h.Salt[:], h.Time, h.Mem, h.Threads)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	hb := make([]byte, headerV1Size)
	copy(hb[0:8], magicV1[:])
	binary.BigEndian.PutUint32(hb[8:12], h.Time)
	binary.BigEndian.PutUint32(hb[12:16], h.Mem)
	hb[16] = h.Threads
	copy(hb[17:], h.Salt[:])

	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	p := sample()
	p.ID = "LEGACY01"
	d := data{Version: 1, Titre: "Base Ancienne", Participants: []Participant{p}}
	plain, _ := json.Marshal(d)
	out := append(hb, nonce...)
	out = gcm.Seal(out, nonce, plain, hb)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. Opening V1 with admin key directly should inform user to open once with user password
	if _, err := OpenAdmin(path, validKeyFormatted); !errors.Is(err, ErrLegacyFormat) {
		t.Fatalf("attendu ErrLegacyFormat, obtenu %v", err)
	}

	// 3. User opens V1 with normal password -> transparent migration to V2!
	s, err := Open(path, pw)
	if err != nil {
		t.Fatalf("Open v1 échoué: %v", err)
	}
	if len(s.List()) != 1 || s.List()[0].ID != "LEGACY01" {
		t.Fatal("données altérées lors de la migration")
	}

	// 4. Verify file on disk is now V2
	raw, _ := os.ReadFile(path)
	if len(raw) < 8 || string(raw[:8]) != string(magicV2[:]) {
		t.Fatal("le fichier sur disque devrait être au format V2")
	}

	// 5. Admin key can now open the migrated database!
	sAdmin, err := OpenAdmin(path, validKeyFormatted)
	if err != nil {
		t.Fatalf("OpenAdmin sur base migrée échoué: %v", err)
	}
	if len(sAdmin.List()) != 1 || sAdmin.List()[0].ID != "LEGACY01" {
		t.Fatal("données introuvables via admin sur base migrée")
	}
}

func TestAdminRecoveryLegacySHA256Fallback(t *testing.T) {
	validKeyFormatted, _ := setupTestAdminKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy_admin.pdb")

	// 1. Crée une base normale
	st, err := Create(path, "motdepasse123", "Test Legacy Fallback", "A", "B", "a@b.fr")
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.Add(Participant{Nom: "LegacyAdmin", Prenom: "Jean", Sexe: "Homme"}, false)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Ré-écrit le slot admin avec l'ancienne dérivation SHA-256 legacy
	adminPubBytes, err := hex.DecodeString(AdminPublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	adminPub, err := ecdh.X25519().NewPublicKey(adminPubBytes)
	if err != nil {
		t.Fatal(err)
	}
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := ephPriv.ECDH(adminPub)
	if err != nil {
		t.Fatal(err)
	}
	legacyKEK := deriveAdminKEK_Legacy(shared)

	// Chiffre la DEK avec legacyKEK
	block, err := aes.NewCipher(legacyKEK)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	var legacyWrapped [60]byte
	nonce := legacyWrapped[:gcm.NonceSize()]
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	gcm.Seal(legacyWrapped[gcm.NonceSize():gcm.NonceSize()], nonce, st.dek, nil)

	var ephPub [32]byte
	copy(ephPub[:], ephPriv.PublicKey().Bytes())

	// Lit et déchiffre le payload d'origine avant modification de l'en-tête
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := openV2(st.dek, blob)
	if err != nil {
		t.Fatal(err)
	}

	// Modifie l'en-tête avec le slot legacy et re-scelle avec AAD
	copy(blob[93:125], ephPub[:])
	copy(blob[125:185], legacyWrapped[:])
	h, err := parseHeaderV2(blob)
	if err != nil {
		t.Fatal(err)
	}
	newBlob, err := sealV2(st.dek, h, plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, newBlob, 0o600); err != nil {
		t.Fatal(err)
	}

	// 3. Ouvre avec OpenAdmin : le déchiffrement HKDF va échouer et basculer sur le fallback Legacy SHA-256
	sAdmin, err := OpenAdmin(path, validKeyFormatted)
	if err != nil {
		t.Fatalf("OpenAdmin sur base legacy admin a échoué : %v", err)
	}
	if !sAdmin.IsAdmin() {
		t.Fatal("sAdmin doit être admin")
	}
	list := sAdmin.List()
	if len(list) != 1 || list[0].Nom != "LegacyAdmin" {
		t.Fatalf("données incorrectes après fallback legacy admin: %+v", list)
	}
}
