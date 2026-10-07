package tabular

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Technosport/Pseudonymisation/internal/store"
	"github.com/xuri/excelize/v2"
	"golang.org/x/text/unicode/norm"
)

// FullHeader est l'ordre des colonnes du classeur Excel d'origine.
var FullHeader = []string{"Nom", "Prénom", "Date de naissance", "Sexe", "Taille (cm)", "Poids (kg)", "Numéro", "Email", "Code Manip", "Date d'ajout", "ID"}

var PseudoHeader = []string{"ID", "Sexe", "Âge", "Taille (cm)", "Poids (kg)", "Code Manip", "Date d'ajout"}

func FullRows(ps []store.Participant) [][]string {
	rows := [][]string{FullHeader}
	for _, p := range ps {
		rows = append(rows, []string{p.Nom, p.Prenom, p.DateNaissance, p.Sexe, p.Taille, p.Poids, p.Telephone, p.Email, p.CodeManip, p.DateAjout, p.ID})
	}
	return rows
}

// PseudoRows exporte uniquement les données pseudonymisées (aucune donnée directement identifiante).
func PseudoRows(ps []store.Participant, at time.Time) [][]string {
	rows := [][]string{PseudoHeader}
	for _, p := range ps {
		age := ""
		if a := store.Age(p.DateNaissance, at); a >= 0 {
			age = strconv.Itoa(a)
		}
		rows = append(rows, []string{p.ID, p.Sexe, age, p.Taille, p.Poids, p.CodeManip, p.DateAjout})
	}
	return rows
}

// WriteCSV écrit en UTF-8 avec BOM et séparateur « ; » (ouverture directe dans Excel en français).
func WriteCSV(w io.Writer, rows [][]string) error {
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	cw.Comma = ';'
	for _, r := range rows {
		out := make([]string, len(r))
		for i, c := range r {
			if strings.HasPrefix(c, "=") || strings.HasPrefix(c, "@") {
				c = "'" + c
			}
			out[i] = c
		}
		if err := cw.Write(out); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func WriteXLSX(w io.Writer, sheet string, rows [][]string) error {
	f := excelize.NewFile()
	defer f.Close()
	if err := f.SetSheetName("Sheet1", sheet); err != nil {
		return err
	}
	for i, r := range rows {
		for j, c := range r {
			cell, err := excelize.CoordinatesToCellName(j+1, i+1)
			if err != nil {
				return err
			}
			if err := f.SetCellStr(sheet, cell, c); err != nil {
				return err
			}
		}
	}
	return f.Write(w)
}

// ReadRows lit un fichier .xlsx/.xlsm ou .csv (séparateur ; , ou tabulation détecté).
func ReadRows(name string, data []byte) ([][]string, error) {
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, ".xlsx"), strings.HasSuffix(n, ".xlsm"):
		f, err := excelize.OpenReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("fichier Excel illisible : %w", err)
		}
		defer f.Close()
		sheets := f.GetSheetList()
		if len(sheets) == 0 {
			return nil, errors.New("classeur vide")
		}
		return f.GetRows(sheets[0], excelize.Options{RawCellValue: true})
	case strings.HasSuffix(n, ".csv"):
		data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
		first := data
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			first = data[:i]
		}
		comma := ';'
		for _, c := range []rune{';', '\t', ','} {
			if bytes.ContainsRune(first, c) {
				comma = c
				break
			}
		}
		cr := csv.NewReader(bytes.NewReader(data))
		cr.Comma = comma
		cr.FieldsPerRecord = -1
		cr.LazyQuotes = true
		return cr.ReadAll()
	}
	return nil, errors.New("format non pris en charge (utiliser .xlsx, .xlsm ou .csv)")
}

func canon(s string) string {
	var b strings.Builder
	for _, r := range norm.NFD.String(strings.ToLower(s)) {
		if unicode.IsLetter(r) && !unicode.Is(unicode.Mn, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var fieldByHeader = map[string]string{
	"nom": "nom", "prenom": "prenom", "datedenaissance": "dob", "sexe": "sexe",
	"taillecm": "taille", "taille": "taille", "poidskg": "poids", "poids": "poids",
	"numero": "tel", "telephone": "tel", "email": "email", "codemanip": "code",
	"datedajout": "ajout", "id": "id",
}

var serial = regexp.MustCompile(`^\d{4,6}(\.\d+)?$`)

// excelDate convertit un numéro de série Excel en AAAA-MM-JJ ; sinon renvoie la valeur telle quelle.
func excelDate(s string) string {
	s = strings.TrimSpace(s)
	if serial.MatchString(s) {
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			return time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC).AddDate(0, 0, int(v)).Format("2006-01-02")
		}
	}
	return s
}

// ParseParticipants repère la ligne d'en-têtes (contenant « Nom ») puis lit les participants.
func ParseParticipants(rows [][]string) ([]store.ImportRecord, error) {
	hdr := -1
	cols := map[string]int{}
	for i, r := range rows {
		m := map[string]int{}
		for j, c := range r {
			if f, ok := fieldByHeader[canon(c)]; ok {
				if _, dup := m[f]; !dup {
					m[f] = j
				}
			}
		}
		if _, ok := m["nom"]; ok && len(m) >= 3 {
			hdr, cols = i, m
			break
		}
		if i > 20 {
			break
		}
	}
	if hdr < 0 {
		return nil, errors.New("en-têtes introuvables : la première ligne doit contenir « Nom », « Prénom », « Date de naissance »…")
	}
	get := func(r []string, f string) string {
		if j, ok := cols[f]; ok && j < len(r) {
			return strings.TrimSpace(r[j])
		}
		return ""
	}
	var recs []store.ImportRecord
	for i := hdr + 1; i < len(rows); i++ {
		r := rows[i]
		p := store.Participant{
			Nom: get(r, "nom"), Prenom: get(r, "prenom"), DateNaissance: excelDate(get(r, "dob")),
			Sexe: get(r, "sexe"), Taille: get(r, "taille"), Poids: get(r, "poids"),
			Telephone: get(r, "tel"), Email: get(r, "email"), CodeManip: get(r, "code"),
			DateAjout: excelDate(get(r, "ajout")), ID: get(r, "id"),
		}
		if p.Nom == "" && p.Prenom == "" && p.ID == "" && p.DateNaissance == "" {
			continue // ligne vide
		}
		recs = append(recs, store.ImportRecord{Row: i + 1, P: p})
	}
	return recs, nil
}
