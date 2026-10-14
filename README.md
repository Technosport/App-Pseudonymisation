# App de Pseudonymisation – Technosport

Application portable pour enregistrer des participants à des expérimentations et leur attribuer un pseudonyme. Fonctionne sur **Windows et Mac**, directement depuis une clé USB, **sans rien installer**. Les données sont chiffrées localement de bout en bout.

---

## 🚀 Utilisation

1. Télécharger la dernière version `App-Pseudonymisation-TKS-vX.Y.Z.zip` dans les [Releases](../../releases).
2. Décompresser le fichier et copier le dossier `App-Pseudonymisation-TKS` sur votre clé USB.
3. Lancer l'application :
   * **Windows** : double-cliquer sur `App-Pseudonymisation-TKS.exe`.
   * **Mac** : double-cliquer sur `Lancer-Mac.command`.

---

## 🔒 Sécurité et Chiffrement

* **Chiffrement par enveloppe (v2)** : Toutes les données sont chiffrées en **AES-256-GCM** avec une clé de données maîtresse (DEK).
* **Dérivation de clé** : Le mot de passe utilisateur dérive une clé de chiffrement via **Argon2id**.
* **Accès de secours (Responsable Scientifique)** : En cas de perte de mot de passe par un chercheur, le Responsable Scientifique peut déverrouiller la base via la clé de secours asymétrique (**Curve25519 / X25519**) et réinitialiser le mot de passe.
* **Zéro fuite sur GitHub** : Seule la clé publique figure dans le dépôt. La clé de secours privée n'est jamais stockée dans le code.

* **Politique de Sécurité & Conformité RGPD** : Consultez le document complet [SECURITY.md](SECURITY.md) pour la matrice d'audit DPO/RSSI et la checklist opérationnelle.

Mode d'emploi complet : [package/README.txt](package/README.txt)

---

## 🔄 Mises à jour automatiques

Dès qu'une nouvelle version est publiée, un bouton vert **« Mise à jour disponible »** apparaît automatiquement dans l'application si l'ordinateur est connecté à Internet. Il permet de télécharger et d'installer la mise à jour en un clic, tout en conservant vos bases et vos sauvegardes intactes.

---

## 🛠️ Structure du projet

* [`cmd/keygen/`](cmd/keygen/) : Générateur autonome de paires de clés de secours (X25519).
* [`cmd/signrelease/`](cmd/signrelease/) : Outil de signature cryptographique Ed25519 pour l'authentification des releases et mises à jour.
* [`internal/store/`](internal/store/) : Moteur de stockage chiffré, dérivation de clés, double enveloppe et sauvegardes automatiques.
* [`internal/server/`](internal/server/) : Serveur HTTP local, API REST et interface utilisateur Web (`web/`).
* [`internal/tabular/`](internal/tabular/) : Analyseur et exportateur universel Excel (`.xlsx`) et CSV.
* [`package/`](package/) : Scripts d'empaquetage et instructions utilisateur pour la distribution clé USB.
* [`icons/`](icons/) : Icônes multiplateformes (Windows `.ico`, Mac `.icns`, Web `.png`/`.svg`).

---

## 💻 Développement

```powershell
# Exécuter tous les tests
go test ./...

# Lancer en mode développement
go run . -data ./dev-data

# Publier une nouvelle version
git tag vX.Y.Z
git push origin vX.Y.Z
```
