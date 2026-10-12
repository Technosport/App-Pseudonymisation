package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

func formatKey(hexKey string) string {
	hexKey = strings.ToUpper(hexKey)
	var parts []string
	for i := 0; i < len(hexKey); i += 4 {
		end := i + 4
		if end > len(hexKey) {
			end = len(hexKey)
		}
		parts = append(parts, hexKey[i:end])
	}
	return "TKSR-" + strings.Join(parts, "-")
}

func main() {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	privHex := hex.EncodeToString(priv.Bytes())
	pubHex := hex.EncodeToString(priv.PublicKey().Bytes())

	fmt.Println("================================================================================")
	fmt.Println("  GÉNÉRATEUR DE CLÉ DE SECOURS - TECHNOSPORT (RESPONSABLE SCIENTIFIQUE)")
	fmt.Println("================================================================================")
	fmt.Println()
	fmt.Println("1. CLÉ DE SECOURS ADMIN (À CONSERVER EN LIEU SÛR PAR LE RESPONSABLE SCIENTIFIQUE) :")
	fmt.Println("   Format formatté :", formatKey(privHex))
	fmt.Println("   Format brut hex :", privHex)
	fmt.Println()
	fmt.Println("2. CLÉ PUBLIQUE (À INTÉGRER DANS LE CODE SOURCE / GITHUB SANS AUCUN DANGER) :")
	fmt.Println("   AdminPublicKeyHex =", pubHex)
	fmt.Println()
	fmt.Println("================================================================================")
}
