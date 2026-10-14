package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	genFlag := flag.Bool("gen", false, "Générer une nouvelle paire de clés Ed25519 pour la signature de releases")
	keyFlag := flag.String("key", "", "Clé privée (pour signer) ou publique (pour vérifier) en hexadécimal")
	fileFlag := flag.String("file", "", "Fichier archive zip à signer ou vérifier")
	sigFlag := flag.String("sig", "", "Fichier de signature .sig (optionnel pour la signature, requis pour -verify)")
	verifyFlag := flag.Bool("verify", false, "Vérifier la signature d'un fichier")
	flag.Parse()

	if *genFlag {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Erreur génération clé:", err)
			os.Exit(1)
		}
		fmt.Println("================================================================================")
		fmt.Println(" NOUVELLE PAIRE DE CLÉS ED25519 - SIGNATURE DE RELEASES TECHNOSPORT")
		fmt.Println("================================================================================")
		fmt.Println()
		fmt.Println("1. CLÉ PUBLIQUE (à inscrire dans ReleasePublicKeyHex dans update.go) :")
		fmt.Println("   " + hex.EncodeToString(pub))
		fmt.Println()
		fmt.Println("2. CLÉ PRIVÉE (à conserver secrètement pour signer les releases GitHub) :")
		fmt.Println("   " + hex.EncodeToString(priv))
		fmt.Println()
		fmt.Println("================================================================================")
		return
	}

	if *fileFlag == "" {
		fmt.Fprintln(os.Stderr, "Erreur : argument -file requis.")
		flag.Usage()
		os.Exit(1)
	}

	data, err := os.ReadFile(*fileFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erreur lecture fichier %s : %v\n", *fileFlag, err)
		os.Exit(1)
	}

	cleanKey := strings.TrimSpace(*keyFlag)
	keyBytes, err := hex.DecodeString(cleanKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erreur décodage clé hexadécimale : %v\n", err)
		os.Exit(1)
	}

	if *verifyFlag {
		if len(keyBytes) != ed25519.PublicKeySize {
			fmt.Fprintf(os.Stderr, "Erreur : la clé publique doit faire %d octets (reçu %d octets)\n", ed25519.PublicKeySize, len(keyBytes))
			os.Exit(1)
		}
		sigFile := *sigFlag
		if sigFile == "" {
			sigFile = *fileFlag + ".sig"
		}
		sigBytes, err := os.ReadFile(sigFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Erreur lecture signature %s : %v\n", sigFile, err)
			os.Exit(1)
		}
		if len(sigBytes) != ed25519.SignatureSize {
			fmt.Fprintf(os.Stderr, "Signature invalide (taille : %d, attendu : %d)\n", len(sigBytes), ed25519.SignatureSize)
			os.Exit(1)
		}
		if !ed25519.Verify(keyBytes, data, sigBytes) {
			fmt.Fprintln(os.Stderr, "ÉCHEC : Signature Ed25519 INVALIDE pour ce fichier !")
			os.Exit(2)
		}
		fmt.Println("SUCCÈS : Signature Ed25519 VALIDE et authentifiée.")
		return
	}

	// Mode signature
	if len(keyBytes) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "Erreur : la clé privée doit faire %d octets (reçu %d octets)\n", ed25519.PrivateKeySize, len(keyBytes))
		os.Exit(1)
	}
	sig := ed25519.Sign(keyBytes, data)
	outSig := *sigFlag
	if outSig == "" {
		outSig = *fileFlag + ".sig"
	}
	if err := os.WriteFile(outSig, sig, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "Erreur écriture signature %s : %v\n", outSig, err)
		os.Exit(1)
	}
	fmt.Printf("Signature créée avec succès : %s (%d octets)\n", outSig, len(sig))
}
