package store

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

type Participant struct {
	ID            string `json:"id"`
	Nom           string `json:"nom"`
	Prenom        string `json:"prenom"`
	DateNaissance string `json:"dateNaissance"` // AAAA-MM-JJ
	Sexe          string `json:"sexe"`
	Taille        string `json:"taille"` // cm
	Poids         string `json:"poids"`  // kg
	Telephone     string `json:"telephone"`
	Email         string `json:"email"`
	CodeManip     string `json:"codeManip"`
	DateAjout     string `json:"dateAjout"` // AAAA-MM-JJ
	ModifieLe     string `json:"modifieLe,omitempty"`
}

var idPattern = regexp.MustCompile(`^[A-Z0-9]{6,16}$`)

var dateLayouts = []string{"2006-01-02", "02/01/2006", "2/1/2006", "02-01-2006", "02.01.2006"}

// ParseDate accepte AAAA-MM-JJ et JJ/MM/AAAA et renvoie AAAA-MM-JJ.
func ParseDate(s string) (string, error) {
	s = strings.TrimSpace(s)
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.Format("2006-01-02"), nil
		}
	}
	return "", fmt.Errorf("date invalide : %q", s)
}

func parseNumber(label, s string, min, max float64) (string, error) {
	s = strings.TrimSpace(strings.ReplaceAll(s, ",", "."))
	if s == "" {
		return "", nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < min || v > max {
		return "", fmt.Errorf("%s invalide (entre %g et %g attendu)", label, min, max)
	}
	return strconv.FormatFloat(v, 'f', -1, 64), nil
}

// Normalize valide et nettoie un participant. L'ID et la date d'ajout ne sont pas gérés ici.
func Normalize(p Participant) (Participant, error) { return normalize(p, false) }

// normalize en mode « lenient » (import de données historiques) conserve un e-mail invalide tel quel.
func normalize(p Participant, lenient bool) (Participant, error) {
	p.Nom = strings.TrimSpace(p.Nom)
	p.Prenom = strings.TrimSpace(p.Prenom)
	p.Telephone = strings.TrimSpace(p.Telephone)
	p.Email = strings.TrimSpace(p.Email)
	p.CodeManip = strings.TrimSpace(p.CodeManip)
	p.Sexe = strings.TrimSpace(p.Sexe)

	if p.Nom == "" {
		return p, errors.New("le nom est obligatoire")
	}
	if p.Prenom == "" {
		return p, errors.New("le prénom est obligatoire")
	}
	var err error
	if strings.TrimSpace(p.DateNaissance) == "" {
		p.DateNaissance = ""
	} else {
		d, err := ParseDate(p.DateNaissance)
		if err != nil {
			return p, errors.New("la date de naissance est invalide")
		}
		if t, _ := time.Parse("2006-01-02", d); t.Year() < 1900 || t.After(time.Now()) {
			return p, errors.New("la date de naissance est hors limites")
		}
		p.DateNaissance = d
	}

	switch strings.ToLower(p.Sexe) {
	case "homme", "h", "m":
		p.Sexe = "Homme"
	case "femme", "f":
		p.Sexe = "Femme"
	default:
		return p, errors.New("le sexe doit être Homme ou Femme")
	}

	if p.Taille, err = parseNumber("la taille", p.Taille, 30, 260); err != nil {
		return p, err
	}
	if p.Poids, err = parseNumber("le poids", p.Poids, 2, 400); err != nil {
		return p, err
	}
	if p.Email != "" && !lenient {
		a, err := mail.ParseAddress(p.Email)
		if err != nil || a.Address != p.Email || !strings.Contains(p.Email[strings.Index(p.Email, "@"):], ".") {
			return p, errors.New("l'adresse e-mail est invalide")
		}
	}
	return p, nil
}

func fold(s string) string {
	var b strings.Builder
	for _, r := range norm.NFD.String(strings.ToLower(strings.TrimSpace(s))) {
		if unicode.Is(unicode.Mn, r) {
			continue
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// identityKey sert à détecter les doublons : nom + prénom + date de naissance.
func identityKey(p Participant) string {
	return fold(p.Nom) + "|" + fold(p.Prenom) + "|" + p.DateNaissance
}

// Age renvoie l'âge en années à la date donnée, ou -1 si la date est invalide.
func Age(dateNaissance string, at time.Time) int {
	t, err := time.Parse("2006-01-02", dateNaissance)
	if err != nil {
		return -1
	}
	a := at.Year() - t.Year()
	if at.Month() < t.Month() || (at.Month() == t.Month() && at.Day() < t.Day()) {
		a--
	}
	return a
}
