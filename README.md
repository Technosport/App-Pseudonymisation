# Pseudonymisation

Application pour enregistrer des participants à des expérimentations et leur attribuer un pseudonyme. Fonctionne sur **Windows et Mac**, depuis une clé USB, **sans rien installer**. Les données sont chiffrées par mot de passe.

## Utiliser

1. Télécharger le dernier fichier `App-Pseudonymisation-TKS-vX.Y.Z.zip` dans les [Releases](../../releases).
2. Le dézipper et copier le dossier `App-Pseudonymisation-TKS` sur la clé USB.
3. Lancer `App-Pseudonymisation-TKS.exe` (Windows) ou `Lancer-Mac.command` (Mac).

## Mises à jour

Déposer simplement le nouveau fichier `.zip` à la racine de la clé USB (ou dans votre dossier d'application). Au prochain lancement, la mise à jour s'applique automatiquement en conservant les données et le mot de passe.

Mode d'emploi complet : [package/LISEZMOI.txt](package/LISEZMOI.txt)

> Mot de passe perdu = données perdues. Ne jamais déposer de données réelles dans ce dépôt.

## Développeurs

`go test ./...` puis `go run . -data ./dev-data`. Une version se publie avec un tag : `git tag v0.1.0 && git push origin v0.1.0`.
