package tabular

import (
	"bytes"
	"testing"
	"time"

	"github.com/Technosport/Pseudonymisation/internal/store"
)

func sample() []store.Participant {
	return []store.Participant{{ID: "ABCD1234", Nom: "Dupont", Prenom: "Éloïse", DateNaissance: "1990-03-12", Sexe: "Femme", Taille: "165", Poids: "60", Telephone: "+33612345678", Email: "e@x.fr", CodeManip: "M1", DateAjout: "2024-01-05"}}
}

func TestExportImportRoundTrip(t *testing.T) {
	for _, name := range []string{"x.csv", "x.xlsx"} {
		var buf bytes.Buffer
		var err error
		if name == "x.csv" {
			err = WriteCSV(&buf, FullRows(sample()))
		} else {
			err = WriteXLSX(&buf, "Liste_Participants", FullRows(sample()))
		}
		if err != nil {
			t.Fatal(err)
		}
		rows, err := ReadRows(name, buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		recs, err := ParseParticipants(rows)
		if err != nil || len(recs) != 1 {
			t.Fatalf("%s: %v %d", name, err, len(recs))
		}
		if got := recs[0].P; got != sample()[0] {
			t.Fatalf("%s: relecture différente\n%+v\n%+v", name, got, sample()[0])
		}
	}
}

func TestLegacyLayoutWithBlankFirstRowAndSerialDates(t *testing.T) {
	rows := [][]string{
		{"", "", ""},
		{"Nom", "Prénom", "Date de naissance", "Sexe", "Taille\n(cm)", "Poids\n(kg)", "Numéro", "Email", "Code Manip", "Date d'ajout", "ID"},
		{"Martin", "Paul", "33000", "Homme", "180", "75", "0600000000", "", "X", "45000", "ZZ99AA11"},
		{"", "", ""},
	}
	recs, err := ParseParticipants(rows)
	if err != nil || len(recs) != 1 {
		t.Fatal(err, len(recs))
	}
	p := recs[0].P
	if p.DateNaissance != "1990-05-07" || p.DateAjout != "2023-03-15" || recs[0].Row != 3 || p.ID != "ZZ99AA11" {
		t.Fatalf("%+v row=%d", p, recs[0].Row)
	}
}

func TestPseudoExportHasNoIdentity(t *testing.T) {
	var buf bytes.Buffer
	WriteCSV(&buf, PseudoRows(sample(), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)))
	s := buf.String()
	for _, bad := range []string{"Dupont", "Éloïse", "1990", "e@x.fr", "+336"} {
		if bytes.Contains(buf.Bytes(), []byte(bad)) {
			t.Fatalf("export pseudonymisé contient %q:\n%s", bad, s)
		}
	}
	if !bytes.Contains(buf.Bytes(), []byte("ABCD1234;Femme;35")) {
		t.Fatalf("contenu inattendu:\n%s", s)
	}
}

func TestBadHeaders(t *testing.T) {
	if _, err := ParseParticipants([][]string{{"a", "b"}}); err == nil {
		t.Fatal("en-têtes absents acceptés")
	}
}
