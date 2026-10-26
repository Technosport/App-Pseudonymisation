# Politique de Sécurité & Matrice de Conformité RGPD

Ce document détaille l'architecture de sécurité, les choix cryptographiques et les mesures techniques et organisationnelles (TOMs) mises en œuvre dans l'application **Pseudonymisation – Technosport**, à destination des chercheurs, du DPO (Délégué à la Protection des Données) et du RSSI (Responsable de la Sécurité des Systèmes d'Information).

---

## 1. Modèle de Menace & Contexte Opérationnel

* **Usage** : Application portable exécutée directement depuis une **clé USB**, hors-ligne, sur des postes hétérogènes (Windows et macOS).
* **Données traitées** : Données de santé et biométrie de sportifs (Nom, Prénom, Date de Naissance, Sexe, Taille, Poids, Tél, Email, Code Manip) associées à un identifiant pseudonyme unique.
* **Menaces considérées** :
  1. *Perte ou vol physique de la clé USB* : tentative d'extraction directe des données brutes hors-ligne.
  2. *Attaque par force brute / dictionnaires GPU* sur le mot de passe utilisateur.
  3. *Attaque de chaîne d'approvisionnement / mise à jour malveillante* via GitHub.
  4. *Inférence et ré-identification statistique* sur les exports d'analyse de petites cohortes.
  5. *Attaques par injection de formules* (CSV Injection / DDE) lors de l'ouverture sous Microsoft Excel.
  6. *Attaque locale sur la boucle loopback* (processus tiers non privilégié sur machine partagée).

---

## 2. Matrice de Conformité Sécurité & RGPD

| Domaine de Sécurité | Mesure Implémentée | Standard / Référence | Statut |
| :--- | :--- | :--- | :---: |
| **Chiffrement au repos (At-Rest)** | Chiffrement authentifié par enveloppe (`PSDB0002`) en **AES-256-GCM** (clé DEK de 256 bits issue de CSPRNG). L'en-tête binaire complet est injecté en **AAD (Additional Authenticated Data)**, interdisant toute altération silencieuse de métadonnées. | ANSSI / NIST SP 800-38D | **Conforme** |
| **Dérivation Mot de Passe** | **Argon2id** (`time=3, mem=64 Mo, threads=4, keyLen=32`) avec sel cryptographique de 128 bits renouvelé à chaque modification de mot de passe. Résistance maximale aux attaques par ASIC/GPU. | RFC 9106 / OWASP | **Conforme** |
| **Hygiène Mémoire Vive (RAM)** | Écrasement explicite (`zeroize`) des clés cryptographiques (`s.dek`, `s.userKey`) et purge totale des données nominatives déchiffrées (`s.d = data{}`) dès le verrouillage ou après **3 minutes d'inactivité** (`WatchIdle`). | CWE-316 (Cleartext Storage in Memory) | **Conforme** |
| **Intégrité des Mises à Jour** | Signature cryptographique **Ed25519** (`cmd/signrelease`) + plafonnement strict (`io.LimitReader` 100 Mo) + protection **Anti-Zip-Slip** + **contrôle strict post-réécriture (taille & CRC32)**, synchronisation disque forcée (`Sync()`) et rollback automatique sous Windows. | RFC 8032 / CWE-22 / CWE-494 | **Conforme** |
| **Cloisonnement Réseau Local** | Écoute exclusive sur `127.0.0.1` (port dynamique aléatoire), filtrage strict de l'en-tête `Host` (Anti-DNS Rebinding), cookies de session `HttpOnly` + `SameSite=Strict`, validation de l'en-tête custom `X-Requested-With` (Anti-CSRF) et `Content-Security-Policy` restrictive. | OWASP Localhost Security | **Conforme** |
| **Protection des Exports (RGPD)** | **Tri alphabétique par Pseudonyme (ID)** brisant la corrélation chronologique avec les plannings et cahiers de paillasse + échappement symétrique sélectif contre l'injection de formules CSV/Excel (`=`, `@`, `+`, `-`, `\t`, `\r`). | Art. 4(5) & Art. 32 RGPD / CWE-1236 | **Conforme** |
| **Résilience & Disponibilité** | Écritures atomiques sur disque (`.tmp` + `f.Sync()` + remplacement atomique `os.Rename`) protégeant contre l'arrachage physique de la clé USB + rotation automatique des sauvegardes chiffrées (`backups/`). | Sécurité opérationnelle | **Conforme** |

---

## 3. Schéma Cryptographique du Format `PSDB0002`

```
                            ┌───────────────────────────────────────────────┐
                            │ DEK (Data Encryption Key) : 256 bits aléatoire│
                            └───────────────────────┬───────────────────────┘
                                                    │
                                          Mot de passe chercheur
                                                    │
                                           Argon2id (time=3, mem=64MB)
                                                    │
                                                    ▼
                                              KEK Utilisateur
                                                    │
                                                    ▼
                                         UserWrappedDEK (AES-GCM)
                                                    │
                                                    ▼
                                       Header V2 (185 octets)
                                                    +
                              Payload JSON chiffré en AES-256-GCM avec la DEK
                              (Header V2 passé en AAD - Additional Authenticated Data)
```
