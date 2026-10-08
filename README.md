# Pseudonymisation

Application pour enregistrer des participants à des expérimentations et leur attribuer un pseudonyme. Fonctionne sur **Windows et Mac**, depuis une clé USB, **sans rien installer**. Les données sont chiffrées par mot de passe.

## Utiliser

1. Télécharger le dernier fichier `App-Pseudonymisation-TKS-vX.Y.Z.zip` dans les [Releases](../../releases).
2. Le dézipper et copier le dossier `App-Pseudonymisation-TKS` sur la clé USB.
3. Lancer `App-Pseudonymisation-TKS.exe` (Windows) ou `Lancer-Mac.command` (Mac).

## Mises à jour

Dès qu'une nouvelle version est publiée, un bouton vert **« Mise à jour disponible »** apparaît automatiquement dans l'application si l'ordinateur est connecté à Internet. Cliquez dessus pour télécharger et installer la mise à jour en un clic, tout en conservant vos données et votre mot de passe.

Mode d'emploi complet : [package/README.txt](package/README.txt)

> Mot de passe perdu = données perdues. Ne jamais déposer de données réelles dans ce dépôt.

## Développeurs

`go test ./...` puis `go run . -data ./dev-data`. Une version se publie avec un tag : `git tag v0.1.0 && git push origin v0.1.0`.
