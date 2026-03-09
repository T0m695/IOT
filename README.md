# Plateforme de Priorisation des Vulnérabilités IoT

Un système automatisé de collecte, enrichissement et priorisation des vulnérabilités affectant les **caméras IP** et autres équipements IoT réseau.

**Cours :** UQAC 8INF917 — Sécurité informatique pour l'Internet des Objets

---

## Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Dépendances](#dépendances)
- [Installation et déploiement](#installation-et-déploiement)
- [Architecture](#architecture)
- [Guide d'utilisation](#guide-dutilisation)
- [Exemples de données](#exemples-de-données)
- [Dépannage](#dépannage)
- [Structure du projet](#structure-du-projet)

---

## Vue d'ensemble

Cette plateforme automatise la collecte de vulnérabilités IoT via trois sources officielles :

| Source | Description | Fréquence |
|--------|-------------|-----------|
| **NIST NVD** | Base de données nationale des vulnérabilités | À chaque requête |
| **CISA KEV** | Vulnérabilités exploitées activement par les hackers | À chaque requête |
| **FIRST EPSS** | Probabilité d'exploitation réelle | À chaque CVE |

### Fonctionnalités

- **Collecte automatisée** : Synchronisation initiale complète + mise à jour quotidienne
- **Enrichissement multi-critères** : Score CVSS (gravité) + EPSS (probabilité) + KEV (exploitation active)
- **Score composite** : Calcul intelligent combinant les trois dimensions
- **Dashboard interactif** : Interface Vue.js avec détails par vulnérabilité
- **Persistance locale** : Base SQLite pour autonomie totale

---

## Dépendances

### Backend (Python)

```
requests >= 2.25.0    # Appels HTTP vers les APIs
sqlite3               # Intégré dans Python
```

### Frontend (Node.js/npm)

```
vue@^3.5.25           # Framework front-end
vue-router@^4.6.4     # Routeur Vue
vite@^7.3.1           # Bundler et serveur dev
@vitejs/plugin-vue@^6.0.2
```

### Système

- **Python 3.8+**
- **Node.js 16+** avec npm
- **Windows 10+** (pour setup.bat avec schtasks)

---

## Installation et déploiement

### Prérequis

Python 3.8+ installé et dans le PATH
Node.js 16+ et npm installés
Accès administrateur Windows (pour la tâche planifiée)

### Étape 1 : Déploiement automatique (RECOMMANDÉ)

**C'est la façon la plus simple !**

1. **Clic droit** sur `setup.bat`
2. **Sélectionner "Exécuter en tant qu'administrateur"**
3. **Cliquer "Oui"** quand demandé par le contrôle de compte d'utilisateur
4. **Attendre la fin** (peut prendre un certain temps)
```
INITIALISATION DU PROJET VULNERABILITES IOT

Installation des modules Python...
Recuperation de l'historique 
Configuration de la recuperation a 00h01 tout les jours

TERMINE !
```

**Ce que setup.bat fait :**
- Installe `requests` via pip
- Lance `fetch_all_time.py` pour récupérer **tout l'historique** des CVE
- Configure une **tâche planifiée Windows** pour mettre à jour les données chaque nuit à 00h01

---

### Étape 2 : Déploiement manuel (optionnel, si setup.bat échoue)

#### A) Installer les dépendances Python

```bash
pip install requests
```

#### B) Remplir la base de données avec l'historique complet

```bash
python fetch_all_time.py
```

**Sortie attendue :**
```
--- Recherche pour : ip camera ---
Catalogue KEV chargé (1536 entrées).
Requête NIST : résultats 0 à 2000...
Requête NIST : résultats 2000 à 4000...
Requête NIST : résultats 4000 à 6000...
...
[continues jusqu'à épuisement des résultats]
```

#### C) Installer les dépendances Node.js

```bash
npm install
```

#### D) Configurer la mise à jour quotidienne (Windows)

```bash
schtasks /create /tn "MAJ_Quotidienne_IoT" /tr "python.exe 'C:CHEMIN_DU_PROJET\fetch.py'" /sc daily /st 00:01 /f
```

---

## Guide d'utilisation

### Lancer le système complet

**Vous devez lancer 2 services en parallèle :**

#### Terminal 1 : API Backend (port 5000)

```bash
cd c:\CHEMIN_DU_PROJET\bdd
python api.py
```

**Résultat attendu :**
```
WARNING: This is a development server. Do not use it in production.
Running on http://127.0.0.1:5000
```

**Laissez ce terminal ouvert** (l'API doit rester active)

---

#### Terminal 2 : Dashboard Frontend (port 5173)

Ouvrez un **nouveau terminal** :

```bash
cd c:\CHEMIN_DU_PROJET\dashboard
npm run dev
```

**Résultat attendu :**
```
VITE v7.3.1  ready in 123 ms

  ➜  Local:   http://localhost:5173/
  ➜  press h + enter to show help
```

**Laissez ce terminal aussi ouvert**

---

#### Navigateur Web

Ouvrez votre navigateur et allez à :

```
http://localhost:5173
```

Vous devriez voir la **liste des vulnérabilités** !

### Votre tableau de bord

```
┌─────────────────────────────────────────────┐
│  Vulnérabilités | Recommandations           │
├─────────────────────────────────────────────┤
│                                             │
│  Liste des vulnérabilités                   │
│                                             │
│  ┌─────────────────────────────────────┐   │
│  │ CVE-XXXX-XXXXX                      │   │
│  │ CVE: CVE-XXXX-XXXXX                 │   │
│  │ Date de collecte: 2026-03-08         │   │
│  │ Score de priorité: [████░░░░] 7.2   │   │
│  └─────────────────────────────────────┘   │
│                                             │
│  (Cliquez sur une CVE pour voir les détails)│
│                                             │
└─────────────────────────────────────────────┘
```

### Voir les détails d'une vulnérabilité

1. **Cliquez** sur une vulnérabilité dans la liste
2. La page affiche :
   - **CVE ID** : Identifiant unique
   - **Score CVSS** : Grave théorique (0-10)
   - **Score EPSS** : Probabilité d'exploitation (0-1)
   - **KEV Actif** : Exploitée par les hackers ? (1 = oui)
   - **Score de priorité** : Combinaison des trois (calculé)
   - **Description complète** : Détails techniques de la faille
   - **CWE** : Types de faiblesses associées

---

## Exemples de données

### Données brutes (SQLite)

**Exemple d'une CVE stockée :**

```sql
SELECT * FROM vuln_iot WHERE cve_id = 'CVE-2024-12345';
```

**Résultat :**
```
cve_id              | CVE-2024-12345
description         | Authentication bypass in IP camera firmware
cvss_impact         | 8.6
epss_prob           | 0.45
kev_actif           | 1
cwe                 | ['CWE-287: Improper Authentication']
priorite_score      | 8.95
date_collecte       | 2026-03-08
```

### Calcul du score de priorité

**Formule :**
```
Score = (CVSS × 0.5) + (EPSS × 10) + (KEV × 3.0)
```

**Exemple concret :**

| Scénario | CVSS | EPSS | KEV | Score | Interprétation |
|----------|------|------|-----|-------|-----------------|
| Faible risque | 3.0 | 0.1 | 0 | **1.6** 🟢 | Non prioritaire |
| Risque moyen | 6.5 | 0.3 | 0 | **6.25** 🟡 | À surveiller |
| Risque élevé | 8.0 | 0.7 | 1 | **12.7** 🔴 | CRITIQUE |
| Risque maximum | 10.0 | 0.95 | 1 | **14.5** 🔴 | IMMÉDIAT |

### Réponse API (`GET /donnees`)

```json
[
  {
    "cve_id": "CVE-2024-12345",
    "description": "Authentication bypass in IP camera firmware",
    "cvss_impact": 8.6,
    "epss_prob": 0.45,
    "kev_actif": 1,
    "cwe": "[...]",
    "priorite_score": 8.95,
    "date_collecte": "2026-03-08"
  },
  {
    "cve_id": "CVE-2024-12346",
    "description": "SQL injection in NVR admin panel",
    "cvss_impact": 7.2,
    "epss_prob": 0.62,
    "kev_actif": 0,
    "cwe": "[...]",
    "priorite_score": 9.6,
    "date_collecte": "2026-03-07"
  }
]
```

---

## Architecture

### Diagramme du pipeline

```
┌──────────────────────────────────────────────────────────┐
│          SOURCES EXTERNES DE DONNÉES                      │
│                                                            │
│  NVD/NIST API    │    CISA KEV Feed    │  FIRST EPSS API  │
└─────────┬────────────────┬───────────────────┬────────────┘
          │                │                   │
          └────────────────┼───────────────────┘
                           │
                           ▼
         ┌─────────────────────────────────────┐
         │   SCRIPTS DE COLLECTE (Python)      │
         │                                     │
         │  fetch_all_time.py (une fois)       │  Récupère l'historique complet
         │  fetch.py (quotidien à 00h01)       │  Met à jour les données récentes
         └──────────────┬──────────────────────┘
                        │
                        ▼
         ┌─────────────────────────────────────┐
         │  BASE DE DONNÉES (SQLite)           │
         │  vulnerabilites_iot.db              │
         │  • 21+ CVEs IoT                     │
         │  • Scores CVSS + EPSS + KEV         │
         │  • Scores de priorité calculés      │
         └──────────────┬──────────────────────┘
                        │
                        ▼
         ┌─────────────────────────────────────┐
         │  API BACKEND (Flask/Python)         │
         │  Port 5000 - /donnees               │
         │  • Lecture BDD                      │
         │  • Sérialisation JSON               │
         │  • CORS activé                      │
         └──────────────┬──────────────────────┘
                        │
                        ▼
         ┌─────────────────────────────────────┐
         │  DASHBOARD WEB (Vue.js + Vite)      │
         │  Port 5173                          │
         │  • Liste des vulnérabilités         │
         │  • Détails par CVE                  │
         │  • Recommandations de sécurité      │
         └─────────────────────────────────────┘
                        │
                        ▼
                    NAVIGATEUR
                    (localhost:5173)
```

### Structure des fichiers

```
IOT/
├── README.md                           # Ce fichier
├── setup.bat                           # Installation automatique (Windows)
├── fetch.py                            # Mise à jour quotidienne (00h01)
├── fetch_all_time.py                   # Récupération historique complète
│
├── bdd/
│   ├── api.py                          # Backend Flask (port 5000)
│   └── vulnerabilites_iot.db           # SQLite (créée au premier lancement)
│
├── dashboard/
│   ├── package.json                    # Dépendances Node.js
│   ├── vite.config.js                  # Config Vite
│   ├── index.html
│   ├── src/
│   │   ├── main.js                     # Point d'entrée Vue
│   │   ├── App.vue                     # Composant racine
│   │   ├── style.css                   # Styles globaux
│   │   ├── components/
│   │   │   ├── Vulnerabilites.vue      # Liste des CVEs
│   │   │   ├── VulnerabiliteDetail.vue # Détails d'une CVE
│   │   │   └── Recommandations.vue     # Conseils de sécurité
│   │   └── router/
│   │       └── index.js                # Configuration Vue Router
│   └── public/
│
└── templates/
    └── index.html                      # Template HTML (optionnel)
```

---

## Dépannage

### "Failed to fetch" dans le dashboard

**Cause :** L'API backend n'est pas lancée ou n'est pas accessible.

**Solution :**
```bash
# Vérifiez que l'API fonctionne
cd bdd
python api.py

# Testez dans votre navigateur
http://localhost:5000/donnees
```

---

### "Aucune donnée trouvée" (mais l'API répond "[]")

**Cause :** La base de données est vide.

**Solution :**
```bash
python fetch_all_time.py
```

Attendez la fin de l'exécution.

---

### "ModuleNotFoundError: No module named 'requests'"

**Cause :** requests n'est pas installé.

**Solution :**
```bash
pip install requests
```

---

### Tâche planifiée ne s'exécute pas

**Cause :** setup.bat n'a pas été lancé en administrateur.

**Solution :**
```bash
# Vérifier que la tâche existe
schtasks /query /tn MAJ_Quotidienne_IoT

# La relancer manuellement
schtasks /run /tn MAJ_Quotidienne_IoT
```

---

### Port 5000 déjà utilisé

**Cause :** Un autre service utilise le port 5000.

**Solution :** Modifiez [bdd/api.py](bdd/api.py#L18) :
```python
if __name__ == '__main__':
    app.run(debug=True, port=5001)  # Changez à 5001
```

Puis modifiez [dashboard/src/components/Vulnerabilites.vue](dashboard/src/components/Vulnerabilites.vue#L41) :
```javascript
const response = await fetch('http://localhost:5001/donnees')
```

---

## Documentation technique

### Scripts Python

#### `fetch.py` - Mise à jour quotidienne

- ⏱S'exécute chaque nuit à **00h01**
- Recherche les CVE modifiées **hier seulement**
- Mots-clés ciblés : "ip camera", "network camera", "NVR", "ONVIF", "Hikvision"
- Rapide (quelques minutes)

#### `fetch_all_time.py` - Synchronisation complète

- S'exécute **une fois uniquement**
- Récupère **TOUT l'historique** (pas de filtre de date)
- Pagination automatique (2000 résultats par requête)
- Lent mais nécessaire pour l'initialisation

### Composants Vue.js

#### `Vulnerabilites.vue` - Liste

- Affiche toutes les CVE sous forme de "cartes"
- Code couleur dynamique pour le score de priorité (vert → rouge)
- Clic sur une carte → navigation vers les détails

#### `VulnerabiliteDetail.vue` - Détails

- Affiche tous les champs d'une CVE sélectionnée
- Description complète en bas
- Lien implicite pour revenir à la liste

---

## Concepts clés

### CVSS (Common Vulnerability Scoring System)
- **Échelle :** 0 à 10
- **Signification :** Gravité **théorique** de la vulnérabilité
- **Exemple :** Une authentification cassée = 8.6
- **Poids dans le score :** 50%

### EPSS (Exploit Prediction Scoring System)
- **Échelle :** 0 à 1 (probabilité)
- **Signification :** Chance que quelqu'un l'exploite **réellement**
- **Exemple :** 0.45 = 45% de chance d'exploitation
- **Poids dans le score :** 100%

### KEV (Known Exploited Vulnerabilities)
- **Valeur :** 0 ou 1
- **Signification :** Exploitée **activement par des hackers** en ce moment
- **Poids dans le score :** +3.0 bonus

### Score de priorité composite
```
Priorité = (CVSS × 0.5) + (EPSS × 10) + (KEV × 3.0)
```

Plus le score est élevé, plus la vulnérabilité est **critique**.

---

## Support

**Pour déboguer :**

1. Consultez les **logs des scripts** (stdout/stderr)
2. Vérifiez la **base de données** :
   ```bash
   python
   import sqlite3
   conn = sqlite3.connect('bdd/vulnerabilites_iot.db')
   cursor = conn.cursor()
   cursor.execute('SELECT COUNT(*) FROM vuln_iot')
   print(cursor.fetchone())
   ```
3. Consultez la **console JavaScript** du navigateur (F12)

---

## ✅ Checklist de démarrage

- [ ] Python 3.8+ installé
- [ ] Node.js 16+ installé
- [ ] setup.bat exécuté en administrateur (OU étapes déploiement manuel complétées)
- [ ] Base de données remplie (fetch_all_time.py terminé)
- [ ] Terminal 1 : `python bdd/api.py` lancé
- [ ] Terminal 2 : `npm run dev` lancé dans le dossier dashboard
- [ ] Navigateur : http://localhost:5173 accessible
- [ ] Vulnérabilités affichées ✅

---
