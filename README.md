# Pseudonymisation

Application simple pour enregistrer des participants à des expérimentations et leur attribuer un identifiant pseudonyme. Fonctionne sur **Windows et Mac**, depuis une clé USB, **sans rien installer**. Les données sont chiffrées par mot de passe.

## Utiliser

1. Télécharger le dernier fichier `Participants-vX.Y.Z.zip` dans les [Releases](../../releases).
2. Le dézipper et copier le dossier `Participants` sur la clé USB.
3. Lancer `Participants.exe` (Windows) ou `Lancer-Mac.command` (Mac).

Mode d'emploi : [package/LISEZMOI.txt](package/LISEZMOI.txt)

> Mot de passe perdu = données perdues. Ne jamais déposer de données réelles dans ce dépôt.

## Développeurs

`go test ./...` puis `go run . -data ./dev-data`. Une version se publie avec un tag : `git tag v0.1.0 && git push origin v0.1.0`.
