package server

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Technosport/Pseudonymisation/internal/store"
	"github.com/Technosport/Pseudonymisation/internal/tabular"
)

//go:embed web
var webFS embed.FS

const (
	cookieName  = "pseudo_session"
	maxUpload   = 20 << 20
	idleTimeout = 3 * time.Minute
)

type Server struct {
	DBPath    string
	BackupDir string
	Version   string

	CheckUpdate func() (any, error)
	ApplyUpdate func(url string) error

	mu       sync.Mutex
	st       *store.Store
	token    string
	closed   bool
	lastPing time.Time
	quit     chan struct{}
	quitOnce sync.Once
}

func New(dbPath, backupDir, version string) *Server {
	return &Server{DBPath: dbPath, BackupDir: backupDir, Version: version, quit: make(chan struct{}), lastPing: time.Now()}
}

// Quit retourne un canal fermé quand l'application doit s'arrêter.
func (s *Server) Quit() <-chan struct{} { return s.quit }

// Close sauvegarde si des modifications ont eu lieu pendant la session.
func (s *Server) Close() error {
	s.mu.Lock()
	st, done := s.st, s.closed
	s.closed = true
	s.mu.Unlock()
	if st != nil && !done && st.Dirty() {
		_, err := st.Backup(s.BackupDir)
		return err
	}
	return nil
}

// WatchIdle arrête l'application si le navigateur n'envoie plus de signal de vie.
func (s *Server) WatchIdle() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.quit:
			return
		case <-t.C:
			s.mu.Lock()
			idle := time.Since(s.lastPing)
			s.mu.Unlock()
			if idle > idleTimeout {
				s.quitOnce.Do(func() { close(s.quit) })
				return
			}
		}
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("GET /", http.FileServerFS(sub))
	mux.HandleFunc("GET /api/ping", s.ping)
	mux.HandleFunc("GET /api/state", s.state)
	mux.HandleFunc("POST /api/setup", s.setup)
	mux.HandleFunc("POST /api/unlock", s.unlock)
	mux.HandleFunc("GET /api/participants", s.auth(s.list))
	mux.HandleFunc("POST /api/participants", s.auth(s.add))
	mux.HandleFunc("PUT /api/participants/{id}", s.auth(s.update))
	mux.HandleFunc("DELETE /api/participants/{id}", s.auth(s.remove))
	mux.HandleFunc("GET /api/export", s.auth(s.export))
	mux.HandleFunc("POST /api/import", s.auth(s.importFile))
	mux.HandleFunc("POST /api/password", s.auth(s.password))
	mux.HandleFunc("GET /api/audit", s.auth(s.auditLog))
	mux.HandleFunc("POST /api/backup", s.auth(s.backup))
	mux.HandleFunc("GET /api/update/check", s.auth(s.checkUpdate))
	mux.HandleFunc("POST /api/update/apply", s.auth(s.applyUpdate))
	mux.HandleFunc("POST /api/quit", s.auth(s.quitHandler))
	return s.guard(mux)
}

// guard bloque les requêtes dont l'en-tête Host n'est pas local (protection DNS rebinding)
// et exige un en-tête personnalisé sur les écritures (protection CSRF).
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil || (host != "127.0.0.1" && host != "localhost") {
			http.Error(w, "hôte non autorisé", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Requested-With") != "pseudonymisation" {
			http.Error(w, "requête refusée", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		s.mu.Lock()
		tok, st := s.token, s.st
		s.mu.Unlock()
		if err != nil || st == nil || tok == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(tok)) != 1 {
			writeErr(w, http.StatusUnauthorized, "session verrouillée")
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func (s *Server) store() *store.Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

func (s *Server) ping(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.lastPing = time.Now()
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"app": "pseudonymisation", "version": s.Version})
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	state := "setup"
	var titre, expNom, expPrenom, expEmail string

	if store.Exists(s.DBPath) {
		state = "locked"
		if metaBytes, err := os.ReadFile(filepath.Join(filepath.Dir(s.DBPath), "meta.json")); err == nil {
			var m map[string]string
			if json.Unmarshal(metaBytes, &m) == nil {
				titre, expNom, expPrenom, expEmail = m["titre"], m["expNom"], m["expPrenom"], m["expEmail"]
			}
		}
	}
	if c, err := r.Cookie(cookieName); err == nil {
		s.mu.Lock()
		st := s.st
		if st != nil && s.token != "" && subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.token)) == 1 {
			state = "unlocked"
		} else {
			st = nil
		}
		s.mu.Unlock()
		if st != nil {
			titre, expNom, expPrenom, expEmail = st.Info()
		}
	}
	writeJSON(w, 200, map[string]any{
		"state":     state,
		"version":   s.Version,
		"titre":     titre,
		"expNom":    expNom,
		"expPrenom": expPrenom,
		"expEmail":  expEmail,
	})
}

func (s *Server) startSession(w http.ResponseWriter, st *store.Store) error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.st, s.token = st, tok
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	return nil
}

type pwBody struct {
	Password  string `json:"password"`
	Old       string `json:"old"`
	New       string `json:"new"`
	Titre     string `json:"titre"`
	ExpNom    string `json:"expNom"`
	ExpPrenom string `json:"expPrenom"`
	ExpEmail  string `json:"expEmail"`
}

func decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	return json.NewDecoder(r.Body).Decode(v)
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var b pwBody
	if decode(r, &b) != nil {
		writeErr(w, 400, "requête invalide")
		return
	}
	if len(b.Password) < 8 {
		writeErr(w, 400, "le mot de passe doit contenir au moins 8 caractères")
		return
	}
	if s.store() != nil {
		writeErr(w, 409, store.ErrExists.Error())
		return
	}
	st, err := store.Create(s.DBPath, b.Password, b.Titre, b.ExpNom, b.ExpPrenom, b.ExpEmail)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	
	// Sauvegarde des métadonnées en clair pour l'écran de connexion
	metaBytes, _ := json.Marshal(map[string]string{
		"titre": b.Titre, "expNom": b.ExpNom, "expPrenom": b.ExpPrenom, "expEmail": b.ExpEmail,
	})
	_ = os.WriteFile(filepath.Join(filepath.Dir(s.DBPath), "meta.json"), metaBytes, 0o644)

	if err := s.startSession(w, st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) unlock(w http.ResponseWriter, r *http.Request) {
	var b pwBody
	if decode(r, &b) != nil {
		writeErr(w, 400, "requête invalide")
		return
	}
	if cur := s.store(); cur != nil {
		if !cur.CheckPassword(b.Password) {
			time.Sleep(time.Second)
			writeErr(w, 401, store.ErrBadPassword.Error())
			return
		}
		if err := s.startSession(w, cur); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	st, err := store.Open(s.DBPath, b.Password)
	if err != nil {
		if errors.Is(err, store.ErrBadPassword) {
			time.Sleep(time.Second)
			writeErr(w, 401, err.Error())
		} else {
			writeErr(w, 500, err.Error())
		}
		return
	}
	// Sauvegarde à chaque ouverture ; un échec ne doit pas empêcher le travail.
	warn := ""
	if _, err := st.Backup(s.BackupDir); err != nil {
		warn = "La sauvegarde automatique a échoué : " + err.Error()
	}
	if err := s.startSession(w, st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "warning": warn})
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	all := s.store().List()
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	// N est le numéro de ligne dans l'ordre d'enregistrement, stable même lors d'une recherche.
	type row struct {
		store.Participant
		N int `json:"n"`
	}
	out := []row{}
	for i, p := range all {
		if q != "" {
			hay := strings.ToLower(strings.Join([]string{p.ID, p.Nom, p.Prenom, p.CodeManip, p.Email, p.Telephone}, " "))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, row{p, i + 1})
	}
	writeJSON(w, 200, map[string]any{"participants": out, "total": len(all)})
}

type pBody struct {
	store.Participant
	Force bool `json:"force"`
}

func (s *Server) saveResult(w http.ResponseWriter, p store.Participant, err error) {
	var de *store.DuplicateError
	switch {
	case errors.As(err, &de):
		writeJSON(w, 409, map[string]any{"error": de.Error(), "duplicates": de.IDs})
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, 404, err.Error())
	case err != nil:
		writeErr(w, 400, err.Error())
	default:
		writeJSON(w, 200, p)
	}
}

func (s *Server) add(w http.ResponseWriter, r *http.Request) {
	var b pBody
	if decode(r, &b) != nil {
		writeErr(w, 400, "requête invalide")
		return
	}
	p, err := s.store().Add(b.Participant, b.Force)
	s.saveResult(w, p, err)
}

func (s *Server) update(w http.ResponseWriter, r *http.Request) {
	var b pBody
	if decode(r, &b) != nil {
		writeErr(w, 400, "requête invalide")
		return
	}
	p, err := s.store().Update(r.PathValue("id"), b.Participant, b.Force)
	s.saveResult(w, p, err)
}

func (s *Server) remove(w http.ResponseWriter, r *http.Request) {
	if err := s.store().Delete(r.PathValue("id")); err != nil {
		s.saveResult(w, store.Participant{}, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	ps := s.store().List()
	mode, format := r.URL.Query().Get("mode"), r.URL.Query().Get("format")
	var rows [][]string
	name := "participants"
	if mode == "pseudo" {
		rows, name = tabular.PseudoRows(ps, time.Now()), "participants_pseudonymises"
	} else {
		rows = tabular.FullRows(ps)
	}
	name += "_" + time.Now().Format("20060102_150405")
	if format == "xlsx" {
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.xlsx"`, name))
		if err := tabular.WriteXLSX(w, "Participants", rows); err != nil {
			http.Error(w, err.Error(), 500)
		}
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, name))
	tabular.WriteCSV(w, rows)
}

func (s *Server) importFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
	f, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, 400, "fichier manquant ou trop volumineux")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		writeErr(w, 400, "lecture impossible")
		return
	}
	rows, err := tabular.ReadRows(filepath.Base(hdr.Filename), data)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	recs, err := tabular.ParseParticipants(rows)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rep, err := s.store().Import(recs)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rep)
}

func (s *Server) password(w http.ResponseWriter, r *http.Request) {
	var b pwBody
	if decode(r, &b) != nil {
		writeErr(w, 400, "requête invalide")
		return
	}
	if err := s.store().ChangePassword(b.Old, b.New); err != nil {
		code := 400
		if errors.Is(err, store.ErrBadPassword) {
			code = 401
		}
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) auditLog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"entries": s.store().Audit(200)})
}

func (s *Server) backup(w http.ResponseWriter, r *http.Request) {
	p, err := s.store().Backup(s.BackupDir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"file": filepath.Base(p)})
}

func (s *Server) quitHandler(w http.ResponseWriter, r *http.Request) {
	err := s.Close()
	msg := ""
	if err != nil {
		msg = "La sauvegarde finale a échoué : " + err.Error()
	}
	writeJSON(w, 200, map[string]any{"ok": true, "warning": msg})
	go s.quitOnce.Do(func() { time.Sleep(300 * time.Millisecond); close(s.quit) })
}

func (s *Server) checkUpdate(w http.ResponseWriter, r *http.Request) {
	if s.CheckUpdate == nil {
		writeJSON(w, 200, map[string]any{"available": false})
		return
	}
	info, err := s.CheckUpdate()
	if err != nil || info == nil {
		writeJSON(w, 200, map[string]any{"available": false})
		return
	}
	writeJSON(w, 200, map[string]any{
		"available": true,
		"info":      info,
	})
}

type applyUpdateReq struct {
	URL string `json:"url"`
}

func (s *Server) applyUpdate(w http.ResponseWriter, r *http.Request) {
	if s.ApplyUpdate == nil {
		writeErr(w, 400, "Mise à jour non supportée")
		return
	}
	var req applyUpdateReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "requête invalide")
		return
	}
	if err := s.ApplyUpdate(req.URL); err != nil {
		writeErr(w, 500, "Erreur de mise à jour: "+err.Error())
		return
	}
	// On répond succès, puis on ferme le serveur
	writeJSON(w, 200, map[string]any{"ok": true})

	// On force l'arrêt après un court délai pour laisser la réponse HTTP partir
	go func() {
		time.Sleep(500 * time.Millisecond)
		s.quitOnce.Do(func() { close(s.quit) })
	}()
}
