# Dashboard Vulnérabilités IoT

Ce projet permet de collecter, stocker et visualiser les vulnérabilités affectant les objets connectés (IoT), en combinant un backend Python (collecte + API Flask + base SQLite) et un frontend Vue.js (dashboard interactif).

## Structure du projet

- **fetch.py** : Script Python pour collecter les vulnérabilités (NIST, CISA KEV) et alimenter la base de données SQLite.
- **bdd/api.py** : API Flask exposant les données de vulnérabilités via `/donnees`.
- **dashboard/** : Application Vue.js affichant les vulnérabilités et recommandations de sécurité.

## Installation & Lancement

### 1. Backend (API Flask)

- Installe les dépendances nécessaires :
  ```bash
  pip install flask flask-cors requests
  ```
- Lance le script de collecte pour initialiser la base :
  ```bash
  python fetch.py
  ```
- Démarre l’API :
  ```bash
  python bdd/api.py
  ```
  L’API sera disponible sur http://localhost:5000/donnees

### 2. Frontend (Vue.js + Vite)

- Va dans le dossier `dashboard` :
  ```bash
  cd dashboard
  ```
- Installe les dépendances :
  ```bash
  npm install
  ```
- Lance le serveur de développement :
  ```bash
  npm run dev
  ```
- Accède à l’application sur http://localhost:5173/

## Fonctionnalités

- Collecte automatisée des vulnérabilités IoT (CVE, scores CVSS, EPSS, KEV…)
- Stockage dans une base SQLite locale
- API REST pour exposer les données
- Dashboard interactif : liste, détails, recommandations de sécurité

## Personnalisation

- Les composants principaux du frontend sont dans `dashboard/src/components/`
  - `Vulnerabilites.vue` : affichage de la liste
  - `VulnerabiliteDetail.vue` : détail d’une vulnérabilité
  - `Recommandations.vue` : conseils de sécurité

## Recommandations de sécurité

- Patching régulier
- Configuration sécurisée
- Segmentation réseau
- Désactivation des services inutiles
- Bonnes pratiques utilisateurs

---

Projet réalisé avec Python, Flask, Vue 3 et Vite.

---
