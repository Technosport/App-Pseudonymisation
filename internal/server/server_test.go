package server

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type client struct {
	t    *testing.T
	base string
	c    *http.Client
}

func newClient(t *testing.T) (*client, *Server, string) {
	dir := t.TempDir()
	srv := New(filepath.Join(dir, "data", "p.pdb"), filepath.Join(dir, "backups"), "test")
	os.MkdirAll(filepath.Join(dir, "data"), 0o700)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	return &client{t, ts.URL, &http.Client{Jar: jar}}, srv, dir
}

func (c *client) do(method, path string, body any, hdr map[string]string) (int, []byte) {
	var rd io.Reader
	if b, ok := body.([]byte); ok {
		rd = bytes.NewReader(b)
	} else if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("X-Requested-With", "pseudonymisation")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestFullFlow(t *testing.T) {
	c, _, dir := newClient(t)

	if code, _ := c.do("GET", "/api/participants", nil, nil); code != 401 {
		t.Fatalf("accès sans session: %d", code)
	}
	if code, _ := c.do("POST", "/api/setup", map[string]string{"password": "court"}, nil); code != 400 {
		t.Fatalf("mot de passe court accepté: %d", code)
	}
	if code, b := c.do("POST", "/api/setup", map[string]string{"password": "motdepasse1"}, nil); code != 200 {
		t.Fatalf("setup: %d %s", code, b)
	}

	p := map[string]string{"nom": "Dupont", "prenom": "Léa", "dateNaissance": "1995-06-01", "sexe": "Femme", "taille": "170", "poids": "62", "codeManip": "A"}
	code, b := c.do("POST", "/api/participants", p, nil)
	if code != 200 {
		t.Fatalf("add: %d %s", code, b)
	}
	var added map[string]any
	json.Unmarshal(b, &added)
	id := added["id"].(string)

	if code, b := c.do("POST", "/api/participants", p, nil); code != 409 || !strings.Contains(string(b), id) {
		t.Fatalf("doublon: %d %s", code, b)
	}
	p["force"] = "true"
	pf := map[string]any{"nom": "Dupont", "prenom": "Léa", "dateNaissance": "1995-06-01", "sexe": "Femme", "force": true}
	if code, _ := c.do("POST", "/api/participants", pf, nil); code != 200 {
		t.Fatal("force refusé")
	}

	if _, b := c.do("GET", "/api/participants?q=zzz", nil, nil); !strings.Contains(string(b), `"participants":[]`) {
		t.Fatalf("recherche: %s", b)
	}

	_, csv := c.do("GET", "/api/export?mode=pseudo&format=csv", nil, nil)
	if strings.Contains(string(csv), "Dupont") || !strings.Contains(string(csv), id) {
		t.Fatalf("export pseudo: %s", csv)
	}
	if code, b := c.do("GET", "/api/export?mode=full&format=xlsx", nil, nil); code != 200 || !bytes.HasPrefix(b, []byte("PK")) {
		t.Fatal("export xlsx")
	}

	// import CSV
	var mp bytes.Buffer
	w := multipart.NewWriter(&mp)
	fw, _ := w.CreateFormFile("file", "in.csv")
	fw.Write([]byte("Nom;Prénom;Date de naissance;Sexe;ID\nMartin;Paul;01/02/1980;Homme;QQQQ1111\n"))
	w.Close()
	code, b = c.do("POST", "/api/import", mp.Bytes(), map[string]string{"Content-Type": w.FormDataContentType()})
	if code != 200 || !strings.Contains(string(b), `"added":1`) {
		t.Fatalf("import: %d %s", code, b)
	}

	if code, _ := c.do("DELETE", "/api/participants/"+id, nil, nil); code != 200 {
		t.Fatal("suppression")
	}
	if code, _ := c.do("POST", "/api/backup", nil, nil); code != 200 {
		t.Fatal("sauvegarde")
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, "backups")); len(ents) != 1 {
		t.Fatalf("sauvegardes: %d", len(ents))
	}
}

func TestSecurityGuards(t *testing.T) {
	c, _, _ := newClient(t)
	c.do("POST", "/api/setup", map[string]string{"password": "motdepasse1"}, nil)

	req, _ := http.NewRequest("GET", c.base+"/api/state", nil)
	req.Host = "evil.com:80"
	resp, err := c.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("Host étranger accepté: %d", resp.StatusCode)
	}

	req, _ = http.NewRequest("POST", c.base+"/api/participants", strings.NewReader("{}"))
	resp, _ = c.c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("écriture sans en-tête CSRF acceptée: %d", resp.StatusCode)
	}
}

func TestUnlockWrongThenRight(t *testing.T) {
	c, _, dir := newClient(t)
	c.do("POST", "/api/setup", map[string]string{"password": "motdepasse1"}, nil)

	// nouvelle instance sur le même fichier = relance de l'application
	srv2 := New(filepath.Join(dir, "data", "p.pdb"), filepath.Join(dir, "backups"), "test")
	ts := httptest.NewServer(srv2.Handler())
	defer ts.Close()
	jar, _ := cookiejar.New(nil)
	c2 := &client{t, ts.URL, &http.Client{Jar: jar}}

	if _, b := c2.do("GET", "/api/state", nil, nil); !strings.Contains(string(b), "locked") {
		t.Fatalf("état: %s", b)
	}
	if code, _ := c2.do("POST", "/api/unlock", map[string]string{"password": "faux"}, nil); code != 401 {
		t.Fatal("mauvais mot de passe accepté")
	}
	if code, _ := c2.do("POST", "/api/unlock", map[string]string{"password": "motdepasse1"}, nil); code != 200 {
		t.Fatal("déverrouillage refusé")
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, "backups")); len(ents) != 1 {
		t.Fatal("sauvegarde à l'ouverture manquante")
	}
}

func TestAdminUnlockFlow(t *testing.T) {
	c, _, dir := newClient(t)
	c.do("POST", "/api/setup", map[string]string{"password": "chercheur_secret"}, nil)

	p := map[string]string{"nom": "Dupont", "prenom": "Léa", "dateNaissance": "1995-06-01", "sexe": "Femme", "taille": "170", "poids": "62"}
	c.do("POST", "/api/participants", p, nil)

	// Relance de l'application
	srv2 := New(filepath.Join(dir, "data", "p.pdb"), filepath.Join(dir, "backups"), "test")
	ts := httptest.NewServer(srv2.Handler())
	defer ts.Close()
	jar, _ := cookiejar.New(nil)
	cAdmin := &client{t, ts.URL, &http.Client{Jar: jar}}

	validKey := "TKSR-E975-17CB-FDEF-063E-A150-2884-666E-E36C-39B7-7156-76D0-74C4-649E-7E25-D926-51BA"

	// Mauvaise clé admin rejetée
	if code, _ := cAdmin.do("POST", "/api/unlock", map[string]any{"password": "mauvaise_cle", "isAdmin": true}, nil); code != 401 {
		t.Fatalf("mauvaise clé admin acceptée: %d", code)
	}

	// Bonne clé admin acceptée
	code, b := cAdmin.do("POST", "/api/unlock", map[string]any{"password": validKey, "isAdmin": true}, nil)
	if code != 200 {
		t.Fatalf("déverrouillage admin refusé: %d %s", code, b)
	}

	// État de session
	code, b = cAdmin.do("GET", "/api/state", nil, nil)
	if code != 200 || !strings.Contains(string(b), `"isAdmin":true`) {
		t.Fatalf("session non reconnue admin: %s", b)
	}

	// Liste des participants accessible en admin
	code, b = cAdmin.do("GET", "/api/participants", nil, nil)
	if code != 200 || !strings.Contains(string(b), "Dupont") {
		t.Fatalf("participants inaccessibles en admin: %s", b)
	}

	// L'admin réinitialise le mot de passe utilisateur sans l'ancien mot de passe
	code, b = cAdmin.do("POST", "/api/password", map[string]string{"new": "nouveau_chercheur_pw"}, nil)
	if code != 200 {
		t.Fatalf("réinitialisation mdp par admin échouée: %d %s", code, b)
	}

	// Journal d'audit contient bien les traces
	_, auditBytes := cAdmin.do("GET", "/api/audit", nil, nil)
	if !strings.Contains(string(auditBytes), "connexion_secours") || !strings.Contains(string(auditBytes), "reinitialisation_mdp") {
		t.Fatalf("traces d'audit manquantes: %s", auditBytes)
	}

	// Le chercheur peut ouvrir avec son nouveau mot de passe
	jarUser, _ := cookiejar.New(nil)
	cUser := &client{t, ts.URL, &http.Client{Jar: jarUser}}
	code, _ = cUser.do("POST", "/api/unlock", map[string]any{"password": "nouveau_chercheur_pw", "isAdmin": false}, nil)
	if code != 200 {
		t.Fatalf("ouverture chercheur avec nouveau mdp refusée: %d", code)
	}
}

