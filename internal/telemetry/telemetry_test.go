package telemetry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestUUIDAndInstanceIDPersistence(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "telem-id-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	c1 := NewClient(tmpDir, "v1.0.0")
	id1 := c1.InstanceID()
	if len(id1) != 36 {
		t.Fatalf("taille UUID invalide : %s", id1)
	}

	// Un second client sur le même dossier doit relire exactement le même instance_id
	c2 := NewClient(tmpDir, "v1.0.0")
	if c2.InstanceID() != id1 {
		t.Fatalf("instance_id non persistant : %s != %s", c2.InstanceID(), id1)
	}
}

func TestDisabledWhenNoCredentials(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "telem-disabled-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	c := NewClient(tmpDir, "v1.0.0")
	c.endpointURL = ""
	c.endpointKey = ""
	if c.Enabled() {
		t.Fatal("le client devrait être désactivé sans clés")
	}
	c.Heartbeat()
	c.StudyCreated(NewUUID(), "Test", "Nom", "a@b.fr")
}

func TestTelemetryQueueOfflineAndFlushFIFO(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "telem-fifo-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	var mu sync.Mutex
	var received []rpcPayload
	online := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/v1/rpc/report_telemetry" {
			t.Errorf("chemin RPC inattendu : %s", r.URL.Path)
		}
		if r.Header.Get("apikey") != "test-pub-key" {
			t.Errorf("en-tête apikey manquant ou invalide")
		}
		mu.Lock()
		isOnline := online
		mu.Unlock()
		if !isOnline {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var p rpcPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Errorf("JSON invalide : %v", err)
		}
		mu.Lock()
		received = append(received, p)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	c := NewClient(tmpDir, "v0.4.0")
	c.endpointURL = ts.URL
	c.endpointKey = "test-pub-key"
	c.client = &http.Client{Timeout: 500 * time.Millisecond}

	// 1. En mode hors-ligne (serveur renvoie 503), l'événement doit aller dans la file sur disque
	ev1 := "DB_CREATED"
	p1 := c.basePayload()
	p1.EventType = &ev1
	c.dispatch(p1)

	qFile := filepath.Join(tmpDir, ".telemetry_queue.json")
	if _, err := os.Stat(qFile); err != nil {
		t.Fatalf("le fichier queue aurait dû être créé hors-ligne : %v", err)
	}

	// 2. Retour en ligne : l'envoi d'un 2e événement doit vider le 1er puis envoyer le 2e dans l'ordre FIFO
	mu.Lock()
	online = true
	mu.Unlock()

	ev2 := "DB_UNLOCKED"
	p2 := c.basePayload()
	p2.EventType = &ev2
	c.dispatch(p2)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("attendu 2 événements reçus après reconnexion, obtenu %d", len(received))
	}
	if *received[0].EventType != "DB_CREATED" || *received[1].EventType != "DB_UNLOCKED" {
		t.Fatalf("ordre FIFO non respecté : %+v", received)
	}
	if _, err := os.Stat(qFile); !os.IsNotExist(err) {
		t.Fatal("le fichier queue aurait dû être supprimé après vidage complet")
	}
}
