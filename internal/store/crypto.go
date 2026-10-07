package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/argon2"
)

// Format du fichier : en-tête (authentifié) | nonce | AES-256-GCM(JSON).
// Les paramètres de dérivation sont dans l'en-tête pour pouvoir les faire évoluer.
var magic = [8]byte{'P', 'S', 'D', 'B', '0', '0', '0', '1'}

const headerSize = 8 + 4 + 4 + 1 + 16

type header struct {
	Time    uint32
	Mem     uint32 // en KiB
	Threads uint8
	Salt    [16]byte
}

func newHeader() (header, error) {
	h := header{Time: 3, Mem: 64 * 1024, Threads: 4}
	_, err := rand.Read(h.Salt[:])
	return h, err
}

func (h header) bytes() []byte {
	b := make([]byte, headerSize)
	copy(b, magic[:])
	binary.BigEndian.PutUint32(b[8:], h.Time)
	binary.BigEndian.PutUint32(b[12:], h.Mem)
	b[16] = h.Threads
	copy(b[17:], h.Salt[:])
	return b
}

var errFormat = errors.New("fichier de données invalide ou corrompu")

func parseHeader(b []byte) (header, error) {
	var h header
	if len(b) < headerSize || string(b[:8]) != string(magic[:]) {
		return h, errFormat
	}
	h.Time = binary.BigEndian.Uint32(b[8:])
	h.Mem = binary.BigEndian.Uint32(b[12:])
	h.Threads = b[16]
	copy(h.Salt[:], b[17:headerSize])
	if h.Time == 0 || h.Time > 20 || h.Mem < 8 || h.Mem > 1024*1024 || h.Threads == 0 {
		return h, errFormat
	}
	return h, nil
}

func deriveKey(password string, h header) []byte {
	return argon2.IDKey([]byte(password), h.Salt[:], h.Time, h.Mem, h.Threads, 32)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func seal(key []byte, h header, plain []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	hb := h.bytes()
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(hb)+len(nonce)+len(plain)+gcm.Overhead())
	out = append(out, hb...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plain, hb), nil
}

func open(key []byte, blob []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < headerSize+gcm.NonceSize() {
		return nil, errFormat
	}
	hb := blob[:headerSize]
	nonce := blob[headerSize : headerSize+gcm.NonceSize()]
	plain, err := gcm.Open(nil, nonce, blob[headerSize+gcm.NonceSize():], hb)
	if err != nil {
		return nil, ErrBadPassword
	}
	return plain, nil
}
