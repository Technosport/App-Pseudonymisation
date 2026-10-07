# Pseudonymisation – base de participants portable

Application locale, chiffrée et sans installation, pour enregistrer les participants à des
expérimentations scientifiques et leur attribuer un identifiant pseudonyme.
Elle remplace le classeur Excel à macros `Participants_TKS.xlsm`.

- **PC (Windows) et Mac** (Intel et Apple Silicon), depuis une clé USB, sans droits administrateur.
- **Aucun prérequis** : un exécutable unique, l'interface s'ouvre dans le navigateur (uniquement en local, `127.0.0.1`, aucune connexion Internet).
- **Données chiffrées** (AES-256-GCM, clé dérivée du mot de passe par Argon2id) : un seul fichier `data/participants.pdb`, identique sur PC et Mac. Le chiffrement ne dépend pas de BitLocker.
- **Écriture atomique** (fichier temporaire + renommage) : une coupure ne corrompt pas la base.
- **Sauvegardes automatiques** chiffrées dans `backups/` (ouverture, fermeture après modification, à la demande ; rotation : 30 récentes + 1 par mois).

## Utilisation

Télécharger `Participants-vX.Y.Z.zip` dans les [Releases](../../releases), le dézipper et copier le dossier `Participants` sur la clé. Mode d'emploi : [package/LISEZMOI.txt](package/LISEZMOI.txt).

```
Participants/
  Participants.exe            (Windows)
  Participants-mac-arm64      (Mac Apple Silicon)
  Participants-mac-intel      (Mac Intel)
  Lancer-Mac.command          (lanceur Mac)
  data/participants.pdb       (créé au premier lancement)
  backups/
```

## Fonctions

Saisie, modification, suppression, recherche ; ID aléatoire à 8 caractères (A–Z, 0–9) généré par `crypto/rand`, unique ; détection des doublons (nom + prénom + date de naissance, sans accents ni casse) ; validation (date, sexe, taille, poids, e-mail) ; vue masquant l'identité ; export complet ou **pseudonymisé** (sans nom, e-mail, téléphone, âge à la place de la date de naissance) en CSV/XLSX ; import CSV/XLSX/XLSM en conservant les ID existants ; journal des modifications (ID et action uniquement, sans donnée personnelle) ; changement de mot de passe.

## Sécurité

- Le serveur n'écoute que sur `127.0.0.1`, refuse les en-têtes `Host` non locaux (DNS rebinding), exige un en-tête personnalisé sur les écritures (CSRF) et un cookie de session `HttpOnly`/`SameSite=Strict`.
- Aucune donnée en clair n'est écrite sur le disque. Les sauvegardes sont des copies du fichier chiffré.
- Mot de passe perdu = données irrécupérables (voulu).

## Développement

Prérequis : Go (voir `go.mod`).

```
go test ./...
go run . -data ./dev-data      # -no-browser pour ne pas ouvrir le navigateur
```

Construire les 3 versions (le workflow `release.yml` le fait automatiquement sur un tag `v*`) :

```
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=0.1.0" -o Participants.exe .
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o Participants-mac-arm64 .
CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o Participants-mac-intel .
```

Publier une version : `git tag v0.1.0 && git push origin v0.1.0`.

Organisation : `internal/store` (modèle, chiffrement, sauvegardes), `internal/tabular` (CSV/XLSX), `internal/server` (API HTTP + interface web embarquée dans `internal/server/web`), `main.go` (lancement).

Ne jamais committer de données réelles : `.gitignore` exclut `*.pdb`, `*.xlsx`, `*.xlsm`, `*.csv`, `data/` et `backups/`.

## Limites connues

- Un seul poste à la fois par clé (pas de partage réseau).
- Au premier lancement sur Mac, macOS demande une confirmation (clic droit > Ouvrir) car l'application n'est pas signée par Apple.
- Une sauvegarde reste ouvrable avec le mot de passe en vigueur au moment où elle a été faite.
