package telemetry

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	EndpointURL = ""
	EndpointKey = ""
)

type Client struct {
	dataDir     string
	version     string
	instanceID  string
	endpointURL string
	endpointKey string
	client      *http.Client
	queueFile   string
	mu          sync.Mutex // protège uniquement l'accès au fichier queueFile sur disque
	sendMu      sync.Mutex // sérialise les envois réseau et le vidage de la file (ordre FIFO garanti)
}

type rpcPayload struct {
	InstanceID        string         `json:"p_instance_id"`
	AppVersion        string         `json:"p_app_version"`
	OSInfo            string         `json:"p_os_info"`
	StudyID           *string        `json:"p_study_id,omitempty"`
	Titre             *string        `json:"p_titre,omitempty"`
	ResponsableNom    *string        `json:"p_responsable_nom,omitempty"`
	ResponsableEmail  *string        `json:"p_responsable_email,omitempty"`
	ParticipantsCount *int           `json:"p_participants_count,omitempty"`
	EventType         *string        `json:"p_event_type,omitempty"`
	EventDetails      map[string]any `json:"p_event_details,omitempty"`
}

// NewClient initialise le client de télémétrie et garantit un instance_id unique persistant.
func NewClient(dataDir, version string) *Client {
	url := strings.TrimRight(strings.TrimSpace(EndpointURL), "/")
	if url == "" {
		url = strings.TrimRight(strings.TrimSpace(os.Getenv("TELEMETRY_URL")), "/")
	}
	key := strings.TrimSpace(EndpointKey)
	if key == "" {
		key = strings.TrimSpace(os.Getenv("TELEMETRY_KEY"))
	}

	c := &Client{
		dataDir:     dataDir,
		version:     version,
		endpointURL: url,
		endpointKey: key,
		client:      &http.Client{Timeout: 4 * time.Second},
		queueFile:   filepath.Join(dataDir, ".telemetry_queue.json"),
	}
	c.instanceID = c.loadOrCreateInstanceID()
	return c
}

// Enabled indique si les identifiants distants ont été configurés.
func (c *Client) Enabled() bool {
	return c.endpointURL != "" && c.endpointKey != ""
}

// InstanceID retourne l'identifiant anonyme unique de cette installation.
func (c *Client) InstanceID() string {
	return c.instanceID
}

func (c *Client) loadOrCreateInstanceID() string {
	idPath := filepath.Join(c.dataDir, ".instance_id")
	if b, err := os.ReadFile(idPath); err == nil {
		s := strings.TrimSpace(string(b))
		if len(s) == 36 && strings.Count(s, "-") == 4 {
			return s
		}
	}
	newID := NewUUID()
	_ = os.WriteFile(idPath, []byte(newID), 0o600)
	return newID
}

// NewUUID génère un UUID v4 standard.
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (c *Client) basePayload() rpcPayload {
	return rpcPayload{
		InstanceID: c.instanceID,
		AppVersion: c.version,
		OSInfo:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// Heartbeat met à jour le statut du device et vide la file d'attente hors-ligne.
func (c *Client) Heartbeat() {
	if !c.Enabled() {
		return
	}
	p := c.basePayload()
	go c.dispatch(p)
}

// StudyCreated enregistre une nouvelle base créée et émet un événement DB_CREATED.
func (c *Client) StudyCreated(studyID, titre, respNom, respEmail string) {
	if !c.Enabled() {
		return
	}
	zero := 0
	ev := "DB_CREATED"
	p := c.basePayload()
	if studyID != "" {
		p.StudyID = &studyID
	}
	p.Titre = &titre
	p.ResponsableNom = &respNom
	p.ResponsableEmail = &respEmail
	p.ParticipantsCount = &zero
	p.EventType = &ev
	p.EventDetails = map[string]any{"titre": titre}
	go c.dispatch(p)
}

// StudyActivity met à jour l'activité et le nombre de participants d'une base.
func (c *Client) StudyActivity(studyID, titre, respNom, respEmail string, count int, eventType string, details map[string]any) {
	if !c.Enabled() {
		return
	}
	p := c.basePayload()
	if studyID != "" {
		p.StudyID = &studyID
	}
	p.Titre = &titre
	p.ResponsableNom = &respNom
	p.ResponsableEmail = &respEmail
	p.ParticipantsCount = &count
	if eventType != "" {
		p.EventType = &eventType
		p.EventDetails = details
	}
	go c.dispatch(p)
}

// dispatch sérialise l'envoi : vide d'abord la file hors-ligne, puis envoie l'événement courant.
func (c *Client) dispatch(p rpcPayload) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	c.flushQueueLocked()
	if err := c.postRPC(p); err != nil {
		c.enqueue(p)
	}
}

func (c *Client) postRPC(payload rpcPayload) error {
	if !c.Enabled() {
		return nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/rest/v1/rpc/report_telemetry", c.endpointURL)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("apikey", c.endpointKey)
	req.Header.Set("Authorization", "Bearer "+c.endpointKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("statut HTTP inattendu: %d (body: %s)", resp.StatusCode, string(bodyBytes))
}

func (c *Client) enqueue(payload rpcPayload) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var items []rpcPayload
	if b, err := os.ReadFile(c.queueFile); err == nil {
		_ = json.Unmarshal(b, &items)
	}
	// Plafond de file d'attente hors-ligne à 200 événements max
	if len(items) >= 200 {
		items = items[len(items)-199:]
	}
	items = append(items, payload)
	data, _ := json.Marshal(items)
	_ = os.WriteFile(c.queueFile, data, 0o600)
}

func (c *Client) flushQueueLocked() {
	c.mu.Lock()
	b, err := os.ReadFile(c.queueFile)
	if err != nil {
		c.mu.Unlock()
		return
	}
	var items []rpcPayload
	if err := json.Unmarshal(b, &items); err != nil || len(items) == 0 {
		_ = os.Remove(c.queueFile)
		c.mu.Unlock()
		return
	}
	// On vide le fichier avant de tenter les envois réseau (hors mutex mu)
	_ = os.Remove(c.queueFile)
	c.mu.Unlock()

	var unsent []rpcPayload
	for i, item := range items {
		if err := c.postRPC(item); err != nil {
			unsent = append(unsent, items[i:]...)
			break
		}
	}

	if len(unsent) > 0 {
		c.mu.Lock()
		var newer []rpcPayload
		if b2, err := os.ReadFile(c.queueFile); err == nil {
			_ = json.Unmarshal(b2, &newer)
		}
		combined := append(unsent, newer...)
		if len(combined) > 200 {
			combined = combined[len(combined)-200:]
		}
		data, _ := json.Marshal(combined)
		_ = os.WriteFile(c.queueFile, data, 0o600)
		c.mu.Unlock()
	}
}
