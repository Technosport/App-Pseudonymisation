package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

var AdminPublicKeyHex = ""

func getAdminPublicKeyHex() string {
	if s := strings.TrimSpace(AdminPublicKeyHex); s != "" {
		return s
	}
	return strings.TrimSpace(os.Getenv("ADMIN_PUBLIC_KEY"))
}

var (
	magicV1 = [8]byte{'P', 'S', 'D', 'B', '0', '0', '0', '1'}
	magicV2 = [8]byte{'P', 'S', 'D', 'B', '0', '0', '0', '2'}
)

const (
	headerV1Size = 8 + 4 + 4 + 1 + 16                // 33 octets
	headerV2Size = 8 + 4 + 4 + 1 + 16 + 60 + 32 + 60 // 185 octets
)

var (
	errFormat       = errors.New("fichier de données invalide ou corrompu")
	ErrBadAdminKey  = errors.New("clé de secours incorrecte ou invalide")
	ErrLegacyFormat = errors.New("cette base utilise l'ancien format (v1) et doit être ouverte au moins une fois avec son mot de passe utilisateur pour activer la clé de secours")
)

type headerV1 struct {
	Time    uint32
	Mem     uint32
	Threads uint8
	Salt    [16]byte
}

type headerV2 struct {
	Time            uint32
	Mem             uint32 // en KiB
	Threads         uint8
	UserSalt        [16]byte
	UserWrappedDEK  [60]byte // Nonce (12) + AES-GCM(DEK 32o + Tag 16o = 48o)
	AdminEphemPub   [32]byte // Clé publique éphémère X25519
	AdminWrappedDEK [60]byte // Nonce (12) + AES-GCM(DEK 32o + Tag 16o = 48o)
}

func parseHeaderV1(b []byte) (headerV1, error) {
	var h headerV1
	if len(b) < headerV1Size || string(b[:8]) != string(magicV1[:]) {
		return h, errFormat
	}
	h.Time = binary.BigEndian.Uint32(b[8:12])
	h.Mem = binary.BigEndian.Uint32(b[12:16])
	h.Threads = b[16]
	copy(h.Salt[:], b[17:headerV1Size])
	if h.Time == 0 || h.Time > 20 || h.Mem < 8 || h.Mem > 1024*1024 || h.Threads == 0 {
		return h, errFormat
	}
	return h, nil
}

func parseHeaderV2(b []byte) (headerV2, error) {
	var h headerV2
	if len(b) < headerV2Size || string(b[:8]) != string(magicV2[:]) {
		return h, errFormat
	}
	h.Time = binary.BigEndian.Uint32(b[8:12])
	h.Mem = binary.BigEndian.Uint32(b[12:16])
	h.Threads = b[16]
	copy(h.UserSalt[:], b[17:33])
	copy(h.UserWrappedDEK[:], b[33:93])
	copy(h.AdminEphemPub[:], b[93:125])
	copy(h.AdminWrappedDEK[:], b[125:185])
	if h.Time == 0 || h.Time > 20 || h.Mem < 8 || h.Mem > 1024*1024 || h.Threads == 0 {
		return h, errFormat
	}
	return h, nil
}

func (h headerV2) bytes() []byte {
	b := make([]byte, headerV2Size)
	copy(b[0:8], magicV2[:])
	binary.BigEndian.PutUint32(b[8:12], h.Time)
	binary.BigEndian.PutUint32(b[12:16], h.Mem)
	b[16] = h.Threads
	copy(b[17:33], h.UserSalt[:])
	copy(b[33:93], h.UserWrappedDEK[:])
	copy(b[93:125], h.AdminEphemPub[:])
	copy(b[125:185], h.AdminWrappedDEK[:])
	return b
}

// ParseRecoveryKey nettoie et décode une clé de secours saisie par le responsable.
// Accepte le format formatté (ex: TKSR-XXXX-XXXX...) ou brut hexadécimal (64 caractères).
func ParseRecoveryKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "TKSR-")
	s = strings.TrimPrefix(s, "tksr-")
	s = strings.TrimPrefix(s, "REC-")
	s = strings.TrimPrefix(s, "rec-")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, ":", "")
	if len(s) != 64 {
		return nil, errors.New("la clé de secours doit comporter 64 caractères hexadécimaux")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("clé de secours invalide (caractères non hexadécimaux)")
	}
	return b, nil
}

func deriveKey(password string, salt []byte, time, mem uint32, threads uint8) []byte {
	return argon2.IDKey([]byte(password), salt, time, mem, threads, 32)
}

func wrapDEKForUser(userKey, dek []byte) ([60]byte, error) {
	var out [60]byte
	block, err := aes.NewCipher(userKey)
	if err != nil {
		return out, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return out, err
	}
	nonce := out[:gcm.NonceSize()]
	if _, err := rand.Read(nonce); err != nil {
		return out, err
	}
	sealed := gcm.Seal(out[gcm.NonceSize():gcm.NonceSize()], nonce, dek, nil)
	if len(sealed) != 48 {
		return out, errors.New("erreur de chiffrement DEK utilisateur")
	}
	return out, nil
}

func unwrapDEKForUser(userKey []byte, wrapped [60]byte) ([]byte, error) {
	block, err := aes.NewCipher(userKey)
	if err != nil {
		return nil, ErrBadPassword
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrBadPassword
	}
	nonce := wrapped[:gcm.NonceSize()]
	ciphertext := wrapped[gcm.NonceSize():]
	dek, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrBadPassword
	}
	return dek, nil
}

func deriveAdminKEK_HKDF(sharedSecret, ephPub, adminPub []byte) ([]byte, error) {
	// Lier les clés publiques dans le paramètre info (RFC 5869 / HPKE RFC 9180)
	info := make([]byte, 0, len("Technosport-Recovery-v2")+len(ephPub)+len(adminPub))
	info = append(info, []byte("Technosport-Recovery-v2")...)
	info = append(info, ephPub...)
	info = append(info, adminPub...)

	reader := hkdf.New(sha256.New, sharedSecret, nil, info)
	kek := make([]byte, 32)
	if _, err := io.ReadFull(reader, kek); err != nil {
		return nil, err
	}
	return kek, nil
}

func deriveAdminKEK_Legacy(sharedSecret []byte) []byte {
	h := sha256.Sum256(append(sharedSecret, []byte("Technosport-Recovery-v2")...))
	kek := make([]byte, 32)
	copy(kek, h[:])
	return kek
}

func deriveAdminSharedSecretFromPub(adminPubHex string) (ephPub [32]byte, aesKey []byte, err error) {
	pubBytes, err := hex.DecodeString(adminPubHex)
	if err != nil {
		return ephPub, nil, err
	}
	adminPub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return ephPub, nil, err
	}
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return ephPub, nil, err
	}
	shared, err := ephPriv.ECDH(adminPub)
	if err != nil {
		return ephPub, nil, err
	}
	defer zeroize(shared)
	copy(ephPub[:], ephPriv.PublicKey().Bytes())

	// Utilise la dérivation standardisée HKDF-SHA256
	aesKey, err = deriveAdminKEK_HKDF(shared, ephPub[:], pubBytes)
	if err != nil {
		return ephPub, nil, err
	}
	return ephPub, aesKey, nil
}

func wrapDEKForAdmin(adminPubHex string, dek []byte) (ephPub [32]byte, wrapped [60]byte, err error) {
	var out [60]byte
	if adminPubHex == "" {
		adminPubHex = getAdminPublicKeyHex()
	}
	if adminPubHex == "" {
		return ephPub, out, nil
	}
	eph, aesKey, err := deriveAdminSharedSecretFromPub(adminPubHex)
	if err != nil {
		return eph, out, err
	}
	defer zeroize(aesKey)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return eph, out, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return eph, out, err
	}
	nonce := out[:gcm.NonceSize()]
	if _, err := rand.Read(nonce); err != nil {
		return eph, out, err
	}
	sealed := gcm.Seal(out[gcm.NonceSize():gcm.NonceSize()], nonce, dek, nil)
	if len(sealed) != 48 {
		return eph, out, errors.New("erreur de chiffrement DEK admin")
	}
	return eph, out, nil
}

func unwrapDEKForAdmin(adminPrivBytes, ephemPubBytes []byte, wrapped [60]byte) ([]byte, error) {
	adminPriv, err := ecdh.X25519().NewPrivateKey(adminPrivBytes)
	if err != nil {
		return nil, ErrBadAdminKey
	}
	ephemPub, err := ecdh.X25519().NewPublicKey(ephemPubBytes)
	if err != nil {
		return nil, ErrBadAdminKey
	}
	shared, err := adminPriv.ECDH(ephemPub)
	if err != nil {
		return nil, ErrBadAdminKey
	}
	defer zeroize(shared)

	adminPubBytes := adminPriv.PublicKey().Bytes()

	// 1. Tentative avec la nouvelle dérivation standardisée HKDF-SHA256
	kekHKDF, errHKDF := deriveAdminKEK_HKDF(shared, ephemPubBytes, adminPubBytes)
	if errHKDF == nil {
		dek, errOpen := unwrapWithKEK(kekHKDF, wrapped)
		zeroize(kekHKDF)
		if errOpen == nil {
			return dek, nil // Déchiffrement réussi avec HKDF
		}
	}

	// 2. Fallback transparent pour les bases PSDB0002 créées avant la mise à jour (SHA-256 legacy)
	kekLegacy := deriveAdminKEK_Legacy(shared)
	defer zeroize(kekLegacy)
	dek, errLegacy := unwrapWithKEK(kekLegacy, wrapped)
	if errLegacy == nil {
		return dek, nil
	}

	return nil, ErrBadAdminKey
}

func unwrapWithKEK(kek []byte, wrapped [60]byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := wrapped[:gcm.NonceSize()]
	ciphertext := wrapped[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func sealV2(dek []byte, h headerV2, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
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

func openV2(dek []byte, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < headerV2Size+gcm.NonceSize() {
		return nil, errFormat
	}
	hb := blob[:headerV2Size]
	nonce := blob[headerV2Size : headerV2Size+gcm.NonceSize()]
	plain, err := gcm.Open(nil, nonce, blob[headerV2Size+gcm.NonceSize():], hb)
	if err != nil {
		return nil, errFormat
	}
	return plain, nil
}

// openV1 gère le déchiffrement des anciennes bases créées avec la version 1.
func openV1(key []byte, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < headerV1Size+gcm.NonceSize() {
		return nil, errFormat
	}
	hb := blob[:headerV1Size]
	nonce := blob[headerV1Size : headerV1Size+gcm.NonceSize()]
	plain, err := gcm.Open(nil, nonce, blob[headerV1Size+gcm.NonceSize():], hb)
	if err != nil {
		return nil, ErrBadPassword
	}
	return plain, nil
}
