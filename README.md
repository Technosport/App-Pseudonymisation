# App-Pseudonymisation

[![Technosport amU](https://img.shields.io/badge/Technosport-amU%20%7C%20ISM-002D62?style=flat-square)](https://github.com/Technosport)
[![Platform](https://img.shields.io/badge/OS-Windows%20%7C%20macOS-009EE2?style=flat-square)](../../releases)
[![Security](https://img.shields.io/badge/Chiffrement-AES--256--GCM-26A669?style=flat-square)](SECURITY.md)

> **Application portable et chiffrée de bout en bout (Windows & macOS) pour enregistrer et pseudonymiser les participants lors des expérimentations, utilisable directement sur clé USB.**  
> *Développée au sein du **Technosport / ISM** (UMR 7287 CNRS — Aix-Marseille Université) • [**Mode d'emploi**](package/README.txt) • [**Sécurité & RGPD**](SECURITY.md)*

---

## 🚀 Démarrage

1. Télécharger la dernière archive `App-Pseudonymisation-TKS-vX.Y.Z.zip` dans les **[Releases](../../releases)**.
2. Décompresser et copier le dossier `App-Pseudonymisation-TKS` sur votre clé USB.
3. Lancer l'application :
   - **Windows** : `App-Pseudonymisation-TKS.exe`
   - **macOS** : `Lancer-Mac.command`

---

## 🔒 Sécurité & Conformité

| Composant | Mécanisme mis en œuvre |
| :--- | :--- |
| **Chiffrement local** | Données chiffrées en **AES-256-GCM** et clé dérivée du mot de passe via **Argon2id**. |
| **Mises à jour sécurisées** | Signature cryptographique (**Ed25519**), contrôle d'intégrité post-écriture (**CRC32**) et synchronisation physique sur disque. |
| **Protection des exports** | Tri par identifiant pseudonyme et protection contre l'injection de formules CSV/Excel. |

> [!NOTE]
> Pour le détail complet de l'architecture cryptographique et de la conformité RGPD, consultez le document [**`SECURITY.md`**](SECURITY.md).
