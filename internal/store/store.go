package store

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrBadPassword = errors.New("mot de passe incorrect")
	ErrNotFound    = errors.New("participant introuvable")
	ErrExists      = errors.New("une base existe déjà à cet emplacement")
)

// DuplicateError indique qu'un participant avec la même identité existe déjà.
type DuplicateError struct{ IDs []string }

func (e *DuplicateError) Error() string {
	return "un participant avec le même nom, prénom et date de naissance existe déjà"
}

type AuditEntry struct {
	Time   string `json:"time"`
	Action string `json:"action"`
	ID     string `json:"id,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type data struct {
	Version      int           `json:"version"`
	Participants []Participant `json:"participants"`
	Audit        []AuditEntry  `json:"audit"`
}

const maxAudit = 5000

type Store struct {
	mu    sync.Mutex
	path  string
	key   []byte
	hdr   header
	d     data
	dirty int
}

const idAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Create initialise une nouvelle base chiffrée.
func Create(path, password string) (*Store, error) {
	if Exists(path) {
		return nil, ErrExists
	}
	h, err := newHeader()
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, hdr: h, key: deriveKey(password, h), d: data{Version: 1}}
	if err := s.save(s.d); err != nil {
		return nil, err
	}
	return s, nil
}

// Open ouvre et déchiffre une base existante.
func Open(path, password string) (*Store, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	h, err := parseHeader(blob)
	if err != nil {
		return nil, err
	}
	key := deriveKey(password, h)
	plain, err := open(key, blob)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, hdr: h, key: key}
	if err := json.Unmarshal(plain, &s.d); err != nil {
		return nil, errFormat
	}
	_ = os.Remove(path + ".tmp")
	return s, nil
}

func (s *Store) save(d data) error {
	plain, err := json.Marshal(d)
	if err != nil {
		return err
	}
	blob, err := seal(s.key, s.hdr, plain)
	if err != nil {
		return err
	}
	return writeAtomic(s.path, blob)
}

func writeAtomic(path string, blob []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// commit applique mutate sur une copie, enregistre, puis remplace l'état en mémoire.
// En cas d'échec d'écriture, l'état en mémoire reste inchangé.
func (s *Store) commit(mutate func(d *data) error) error {
	nd := data{
		Version:      s.d.Version,
		Participants: append([]Participant(nil), s.d.Participants...),
		Audit:        append([]AuditEntry(nil), s.d.Audit...),
	}
	if err := mutate(&nd); err != nil {
		return err
	}
	if len(nd.Audit) > maxAudit {
		nd.Audit = nd.Audit[len(nd.Audit)-maxAudit:]
	}
	if err := s.save(nd); err != nil {
		return fmt.Errorf("écriture impossible : %w", err)
	}
	s.d = nd
	s.dirty++
	return nil
}

func now() string   { return time.Now().Format(time.RFC3339) }
func today() string { return time.Now().Format("2006-01-02") }

func audit(d *data, action, id, detail string) {
	d.Audit = append(d.Audit, AuditEntry{Time: now(), Action: action, ID: id, Detail: detail})
}

func newID(taken map[string]bool) (string, error) {
	for {
		b := make([]byte, 8)
		for i := range b {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(idAlphabet))))
			if err != nil {
				return "", err
			}
			b[i] = idAlphabet[n.Int64()]
		}
		if id := string(b); !taken[id] {
			return id, nil
		}
	}
}

func idSet(ps []Participant) map[string]bool {
	m := make(map[string]bool, len(ps))
	for _, p := range ps {
		m[p.ID] = true
	}
	return m
}

func duplicates(ps []Participant, p Participant, exceptID string) []string {
	k := identityKey(p)
	var ids []string
	for _, q := range ps {
		if q.ID != exceptID && identityKey(q) == k {
			ids = append(ids, q.ID)
		}
	}
	return ids
}

func (s *Store) List() []Participant {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Participant(nil), s.d.Participants...)
}

func (s *Store) Get(id string) (Participant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.d.Participants {
		if p.ID == id {
			return p, nil
		}
	}
	return Participant{}, ErrNotFound
}

// Add ajoute un participant. Sans force, un doublon d'identité renvoie *DuplicateError.
func (s *Store) Add(p Participant, force bool) (Participant, error) {
	p, err := Normalize(p)
	if err != nil {
		return p, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ids := duplicates(s.d.Participants, p, ""); len(ids) > 0 && !force {
		return p, &DuplicateError{IDs: ids}
	}
	err = s.commit(func(d *data) error {
		id, err := newID(idSet(d.Participants))
		if err != nil {
			return err
		}
		p.ID = id
		p.DateAjout = today()
		p.ModifieLe = ""
		d.Participants = append(d.Participants, p)
		audit(d, "ajout", id, "")
		return nil
	})
	return p, err
}

// Update modifie un participant existant (l'ID et la date d'ajout sont conservés).
func (s *Store) Update(id string, p Participant, force bool) (Participant, error) {
	p, err := Normalize(p)
	if err != nil {
		return p, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ids := duplicates(s.d.Participants, p, id); len(ids) > 0 && !force {
		return p, &DuplicateError{IDs: ids}
	}
	err = s.commit(func(d *data) error {
		for i := range d.Participants {
			if d.Participants[i].ID == id {
				p.ID = id
				p.DateAjout = d.Participants[i].DateAjout
				p.ModifieLe = today()
				d.Participants[i] = p
				audit(d, "modification", id, "")
				return nil
			}
		}
		return ErrNotFound
	})
	return p, err
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commit(func(d *data) error {
		for i := range d.Participants {
			if d.Participants[i].ID == id {
				d.Participants = append(d.Participants[:i], d.Participants[i+1:]...)
				audit(d, "suppression", id, "")
				return nil
			}
		}
		return ErrNotFound
	})
}

type ImportRecord struct {
	Row int
	P   Participant
}

type ImportReport struct {
	Added      int      `json:"added"`
	Duplicates int      `json:"duplicates"`
	NewIDs     int      `json:"newIds"` // ID absent ou déjà pris : un nouvel ID a été généré
	Errors     []string `json:"errors"`
}

// Import ajoute des participants en une seule écriture. Les doublons d'identité sont ignorés.
func (s *Store) Import(recs []ImportRecord) (ImportReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep := ImportReport{Errors: []string{}}
	err := s.commit(func(d *data) error {
		taken := idSet(d.Participants)
		seen := map[string]bool{}
		for _, p := range d.Participants {
			seen[identityKey(p)] = true
		}
		for _, r := range recs {
			p, err := Normalize(r.P)
			if err != nil {
				rep.Errors = append(rep.Errors, fmt.Sprintf("ligne %d : %v", r.Row, err))
				continue
			}
			if seen[identityKey(p)] {
				rep.Duplicates++
				continue
			}
			p.ID = strings.ToUpper(strings.TrimSpace(r.P.ID))
			if !idPattern.MatchString(p.ID) || taken[p.ID] {
				id, err := newID(taken)
				if err != nil {
					return err
				}
				p.ID = id
				rep.NewIDs++
			}
			if d2, err := ParseDate(r.P.DateAjout); err == nil {
				p.DateAjout = d2
			} else {
				p.DateAjout = today()
			}
			p.ModifieLe = ""
			taken[p.ID] = true
			seen[identityKey(p)] = true
			d.Participants = append(d.Participants, p)
			rep.Added++
		}
		if rep.Added > 0 {
			audit(d, "import", "", fmt.Sprintf("%d participants", rep.Added))
		}
		return nil
	})
	if err != nil {
		return ImportReport{Errors: []string{}}, err
	}
	return rep, nil
}

func (s *Store) Audit(limit int) []AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.d.Audit
	if limit > 0 && len(a) > limit {
		a = a[len(a)-limit:]
	}
	out := append([]AuditEntry(nil), a...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time > out[j].Time })
	return out
}

func (s *Store) CheckPassword(password string) bool {
	s.mu.Lock()
	h := s.hdr
	key := s.key
	s.mu.Unlock()
	return subtle.ConstantTimeCompare(deriveKey(password, h), key) == 1
}

// ChangePassword re-chiffre la base avec un nouveau mot de passe (nouveau sel).
func (s *Store) ChangePassword(oldPw, newPw string) error {
	if !s.CheckPassword(oldPw) {
		return ErrBadPassword
	}
	if len(newPw) < 8 {
		return errors.New("le mot de passe doit contenir au moins 8 caractères")
	}
	h, err := newHeader()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	oldKey, oldHdr := s.key, s.hdr
	s.key, s.hdr = deriveKey(newPw, h), h
	if err := s.save(s.d); err != nil {
		s.key, s.hdr = oldKey, oldHdr
		return err
	}
	s.dirty++
	return nil
}

// Dirty indique si des modifications ont été faites depuis l'ouverture.
func (s *Store) Dirty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dirty > 0
}

func (s *Store) Path() string { return s.path }
