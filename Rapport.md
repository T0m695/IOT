# Rapport Technique — Pipeline de Collecte et de Priorisation des Vulnérabilités IoT
**Cours :** UQAC 8INF917 — Sécurité informatique pour l'Internet des Objets  
**Projet :** Plateforme de priorisation des vulnérabilités IoT  
**Périmètre :** Caméras IP  
**Composants documentés :** `fetch_all_time.py`, `fetch.py`, `setup.bat`

---

## 1. Introduction

Ce rapport décrit l'architecture et le fonctionnement du pipeline de collecte de données. L'application présente : acquisition automatisée des données, enrichissement des entrées CVE, calcul d'un score de priorisation composite, persistance en base de données locale, récupération des données de la base, affichage et filtrage des données.


L'objectif du pipeline est de répondre aux exigences du MVP défini dans l'énoncé : collecte automatique depuis des sources ouvertes, enrichissement multi-critères (CVSS, EPSS, KEV), calcul de priorité, et stockage documenté dans une base SQLite.

---

## 2. Architecture générale du pipeline

Le pipeline se décompose en trois couches fonctionnelles distinctes :

```
┌─────────────────────────────────────────────────────┐
│                   SOURCES EXTERNES                  │
│  NVD/NIST API  │  CISA KEV Feed  │  FIRST EPSS API  │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│              SCRIPTS DE COLLECTE (Python)           │
│fetch_all_time.py (une fois)  │  fetch.py (quotidien)│
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│           BASE DE DONNÉES LOCALE (SQLite)           │
│             vulnerabilites_iot.db                   │
└─────────────────────────────────────────────────────┘
```

### 2.1 Rôle de chaque composant

| Fichier | Rôle | Déclenchement |
|---|---|---|
| `setup.bat` | Initialisation de l'environnement, déploiement de la tâche planifiée | Manuel (une fois) |
| `fetch_all_time.py` | Collecte historique complète depuis NVD | Manuel (une fois) |
| `fetch.py` | Collecte différentielle quotidienne (J-1) | Automatique (00h01) |

---

## 3. Déploiement et initialisation — `setup.bat`

Le fichier `setup.bat` est le point d'entrée du déploiement sur Windows. Il orchestre trois étapes séquentielles :

### 3.1 Fonctionnement

```bat
pip install requests
python fetch_all_time.py
schtasks /create /tn "MAJ_Quotidienne_IoT" /tr "python.exe '%~dp0fetch.py'" /sc daily /st 00:01 /f
```

1. **Installation de la dépendance** : La bibliothèque `requests` est installée via `pip`. 

2. **Collecte historique initiale** : `fetch_all_time.py` est exécuté pour remplir la base de données avec l'intégralité des CVE historiques correspondant aux caméras IP.

3. **Planification de la tâche quotidienne** : La commande `schtasks` Windows crée une tâche planifiée nommée `MAJ_Quotidienne_IoT` qui exécute `fetch.py` chaque jour à 00h01. `/f` force à supprimer la tâche si elle existe déjà.

4. - **Création du chemin** : L'utilisation de `%~dp0` comme chemin de base permet de référencer `fetch.py` depuis son propre répertoire.

### 3.2 Observations et limites

- Le script est **Windows-only** (utilisation de `schtasks`). Pour une portabilité Linux/macOS, il faudrait utiliser `cron`, de la manière qui suit :
```bat
crontab -e
01 00 * * * /usr/bin/python3 /CheminVersLeFichier/fetch.py
```

---

## 4. Collecte historique complète — `fetch_all_time.py`

### 4.1 Objectif

Ce script a pour but d'effectuer une **collecte initiale exhaustive** de toutes les CVE référencées dans la base NVD pour les mots-clé `"ip camera"`, `"network camera"`, `"NVR"`, `"ONVIF"`, `"Hikvision"`. Avoir tout ces mots permet d'avoir plus de résultats, plutôt que de n'avoir que les résultats plus restreint avec `"ip camera"`. Il s'exécute une seule fois lors du déploiement et peut prendre plusieurs minutes selon le volume de données. La structure permet de remplacer ces mots par le modèle exacte d'une caméra si nécessaire.

### 4.2 Schéma de la base de données

La fonction `initialiser_bdd()` crée la table `vuln_iot` dans le fichier `vulnerabilites_iot.db` :

```sql
CREATE TABLE IF NOT EXISTS vuln_iot (
    cve_id       TEXT PRIMARY KEY,
    description  TEXT,
    cvss_impact  REAL,
    epss_prob    REAL,
    kev_actif    INTEGER,
    cwe          TEXT,
    priorite_score REAL,
    date_collecte  TEXT
)
```

Chaque ligne représente une CVE unique. La clé primaire `cve_id` garantit l'unicité. L'instruction `INSERT OR REPLACE` permet de mettre à jour une entrée si elle est retraitée ultérieurement, important surtout pour l'EPSS.

| Champ | Type | Description |
|---|---|---|
| `cve_id` | TEXTE (Pirmary Key) | Identifiant officiel CVE |
| `description` | TEXTE | Description textuelle de la vulnérabilité |
| `cvss_impact` | REEL | Score CVSS v3 (0.0 – 10.0) |
| `epss_prob` | REEL | Score EPSS (probabilité d'exploitation, 0.0 – 1.0) |
| `kev_actif` | ENTIER | Présence dans le catalogue CISA KEV (0 ou 1) |
| `cwe` | TEXTE | Catégorie(s) de faiblesse CWE associée(s) |
| `priorite_score` | REEL | Score composite de priorisation calculé |
| `date_collecte` | TEXTE | Date de collecte (format YYYY-MM-DD) |

### 4.3 Mécanisme de pagination

L'API NVD impose une limite de résultats par requête. Le script gère cela avec une boucle de pagination :

```python
while continuer:
    params_nist = {
        "keywordSearch": perimetre,
        "startIndex": index,
        "resultsPerPage": 2000
    }
    # ...
    index += 2000
    time.sleep(6)
```

Le paramètre `resultsPerPage` est fixé à 2000, qui correspond au maximum autorisé par l'API NVD (ce qui a été testé). L'indice `startIndex` avance de 2000 à chaque itération. La boucle s'arrête dès que l'API renvoie un tableau vide, car cela indique que tout a été récupéré.

Le `time.sleep(6)` est essentiel pour éviter les erreurs : l'API NVD impose un rate limit de 5 requêtes par fenêtre de 30 secondes sans clé API, ce qui est notre cas. Ce délai de 6 secondes entre chaque page respecte cette contrainte et évite les blocages et donc les erreurs.

### 4.4 Enrichissement par CVE

Pour chaque entrée CVE récupérée, le script effectue un **enrichissement en trois étapes** :

**Étape 1 — Score CVSS :**  
Le script tente de récupérer d'abord un score CVSSv3.1, puis à défaut un CVSSv3.0 :
```python
cvss_v3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
cvss_score = cvss_v3[0]["cvssData"]["baseScore"] if cvss_v3 else 0.0
```
Si aucun score v3 n'est disponible (CVE anciennes utilisant CVSS v2), le score est mis à `0.0`. C'est une simplification importante, justifié par le fait que l'application se concentre sur la mise à jour des vulnérabilités.

**Étape 2 — Score EPSS :**  
Pour chaque CVE, une requête individuelle est envoyée à l'API FIRST :
```python
res_e = requests.get(f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=5)
epss_score = float(e_data[0].get("epss", 0.0)) if e_data else 0.0
```
L'EPSS (Exploit Prediction Scoring System) fournit une probabilité comprise entre 0 et 1 représentant la vraisemblance qu'une CVE soit effectivement exploitée dans les 30 prochains jours. Cette valeur est fournie par FIRST.org et est mise à jour quotidiennement.

**Étape 3 — Vérification KEV (CISA) :**  
Le catalogue KEV est téléchargé une seule fois en début d'exécution, puis chaque CVE est vérifiée par une recherche dans la liste en mémoire :
```python
est_dans_kev = 1 if any(v.get("cveID") == cve_id for v in kev_catalog) else 0
```
La présence dans le KEV indique qu'une vulnérabilité est **activement exploitée**, ce qui constitue un signal d'alerte maximal.

---

## 5. Collecte quotidienne différentielle — `fetch.py`

### 5.1 Objectif

Une fois la base initialisée, `fetch.py` va maintenir la base à jour **chaque jour**. Contrairement à `fetch_all_time.py`, il ne collecte que les CVE **modifiées ou publiées la veille** :

```python
hier = datetime.now() - timedelta(days=1)
date_str = hier.strftime("%Y-%m-%d")

params_nist = {
    "keywordSearch": perimetre,
    "lastModStartDate": f"{date_str}T00:00:00.000Z",
    "lastModEndDate":   f"{date_str}T23:59:59.999Z"
}
```

Ce filtrage par date (`lastModStartDate` / `lastModEndDate`) est une fonctionnalité  de l'API NVD v2.0 qui permet de récupérer uniquement les enregistrements modifiés dans une plage temporelle donnée, réduisant le volume de données et le temps d'exécution.

### 5.2 Pipeline identique, périmètre réduit

La logique d'enrichissement (CVSS, EPSS, KEV) est identique à `fetch_all_time.py`. La différence majeure est l'absence de boucle de pagination : pour une fenêtre d'un jour, le volume de CVE concernant les caméras IP est suffisamment faible pour tenir dans une seule page de résultats.

```python
print(f"Base de données mise à jour : {len(vulnerabilites)} CVE traitées.")
```

Le script se termine par un log indiquant le nombre de CVE traitées, utile pour vérifier le bon déroulement.

### 5.3 Mise à jour

L'utilisation de `INSERT OR REPLACE` garantit que si une CVE déjà présente en base est modifiée dans NVD (score révisé, description enrichie), l'entrée sera **mise à jour** plutôt que dupliquée. C'est une propriété importante pour la fiabilité à long terme de la base.

---

## 6. Modèle de priorisation

### 6.1 Formule

Le score de priorisation composite est calculé de la manière suivante :

```
priorite = (cvss_score × 0.5) + (epss_score × 10) + (kev_actif × 3.0)
```

### 6.2 Analyse des composantes

| Composante | Source | Poids | Justification |
|---|---|---|---|
| CVSS × 0.5 | NVD/NIST | Max ~5.0 | Mesure la sévérité. Divisé par 2 pour ne pas être dominant. |
| EPSS × 10 | FIRST.org | Max ~10.0 | Probabilité d'exploitation à 30 jours. Multiplié pour compenser la plage 0–1. |
| KEV × 3.0 | CISA | 0 ou 3.0 | Bonus fixe pour exploitation confirmée dans la nature. |

Le score maximal théorique est d'environ **18.0** (CVSS 10.0 → 5.0 + EPSS 1.0 → 10.0 + KEV → 3.0).

### 6.3 Priorisation

Cette formule implémente les exigences du projet : elle ne se limite pas au CVSS (qui mesure une sévérité théorique), mais intègre :
- **L'exploitation réelle et confirmée** via le KEV, qui représente le signal d'alerte le plus fort.
- **La probabilité d'exploitation future** via l'EPSS, qui permet d'anticiper les menaces émergentes même en l'absence d'exploitation confirmée.

Une CVE avec un CVSS modéré (6.0) mais un EPSS élevé (0.7) et présente dans le KEV obtiendrait un score de `3.0 + 7.0 + 3.0 = 13.0`, surpassant une CVE critique théorique (CVSS 10.0) mais non exploitée (`5.0 + 0.0 + 0.0 = 5.0`). Cette logique est cohérente avec les recommandations du NIST et de CISA.

---




## 7. Architecture de l'interface web et de l'API

### 7.1 Vue d'ensemble de la stack

L'interface utilisateur repose sur une architecture découplée classique de type **SPA (Single Page Application)** :

```
┌─────────────────────────────────────────────────────┐
│              INTERFACE WEB (Vue.js 3)               │
│  Vulnerabilites.vue  │  VulnerabiliteDetail.vue     │
│           Recommandations.vue                       │
└────────────────────────┬────────────────────────────┘
                         │ HTTP / JSON
                         ▼
┌─────────────────────────────────────────────────────┐
│              API REST (Flask / Python)              │
│                  app.py — /donnees                  │
└────────────────────────┬────────────────────────────┘
                         │ SQLite
                         ▼
┌─────────────────────────────────────────────────────┐
│           BASE DE DONNÉES LOCALE (SQLite)           │
│             vulnerabilites_iot.db                   │
└─────────────────────────────────────────────────────┘
```

Flask offre une mise en œuvre rapide d'une API REST, tandis que Vue.js 3 permet de construire une interface réactive.

### 7.2 API REST — app.py

L'API est implémentée avec Flask et expose un unique endpoint GET :

```python
@app.route('/donnees', methods=['GET'])
def get_donnees():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM vuln_iot')
    rows = cursor.fetchall()
    conn.close()
    result = [dict(row) for row in rows]
    return jsonify(result)
```

La configuration `conn.row_factory = sqlite3.Row` permet de sérialiser chaque ligne SQLite en dictionnaire Python, qui est ensuite converti en JSON par `jsonify`. La gestion CORS est activée via `flask_cors`, ce qui autorise les requêtes cross-origin émises par le front Vue.js tournant sur un port distinct.

**Point notable :** la route `/donnees` retourne l'intégralité des entrées de la base sans pagination ni filtrage serveur. Pour un volume de données modéré (quelques milliers de CVE), cette approche est acceptable. Pour une mise à l'échelle, il serait préférable d'implémenter des paramètres de filtrage et de pagination côté API.

### 7.3 Routage Vue.js

Le routeur Vue Router définit trois routes correspondant aux trois vues de l'application :

| Route | Composant | Description |
|---|---|---|
| `/` | Vulnerabilites.vue | Liste paginée des vulnérabilités |
| `/vulnerabilite/:id` | VulnerabiliteDetail.vue | Fiche détaillée d'une CVE |
| `/recommandations` | Recommandations.vue | Page de recommandations de sécurité |

L'utilisation de `createWebHistory()` permet de bénéficier d'URLs propres sans hash.

### 7.4 Vue liste des vulnérabilités — Vulnerabilites.vue

`la composante Vulnerabilites.vue` est la page d'accueil de l'application. Il récupère les données depuis l'API au montage du composant (`onMounted`) et affiche les vulnérabilités sous forme de cartes cliquables.

Une fonctionnalité est le **codage couleur dynamique** du score de priorité :

```javascript
function getPriorityColor(score) {
  const s = Math.max(0, Math.min(10, Number(score)));
  const r = Math.round(46 + (231 - 46) * (s / 10));
  const g = Math.round(204 + (76 - 204) * (s / 10));
  const b = Math.round(64 + (60 - 64) * (s / 10));
  return `rgb(${r},${g},${b})`;
}
```

Cette fonction réalise une interpolation linéaire entre le vert (`rgb(46, 204, 64)`) pour un score de 0 et le rouge (`rgb(231, 76, 60)`) pour un score de 10. Ce retour visuel permet à l'utilisateur d'identifier d'un coup d'œil les vulnérabilités les plus critiques, sans avoir à lire les valeurs numériques.

La navigation vers la fiche détaillée s'effectue via un `router.push` déclenché au clic sur la carte :

```javascript
const goToDetail = (id) => {
  router.push({ name: 'VulnerabiliteDetail', params: { id } })
}
```

### 7.5 Vue détail d'une vulnérabilité — VulnerabiliteDetail.vue

Ce composant affiche la fiche complète d'une CVE sélectionnée. L'identifiant est récupéré depuis les paramètres de route (`route.params.id`), puis la CVE correspondante est retrouvée côté client par filtrage du tableau complet :

```javascript
vuln.value = data.find(v => v.cve_id == id)
```

Cette approche de **filtrage client** est efficace pour le volume de données actuel. La fiche affiche l'ensemble des champs de la base de données, avec une mise en évidence de la description dans un bloc.

Le mapping `fieldLabels` permet une présentation lisible des noms de champs techniques :

```javascript
const fieldLabels = {
  cve_id: 'CVE',
  cvss_impact: 'Score CVSS',
  cwe: 'ID CWE',
  epss_prob: 'Probabilité EPSS',
  kev_actif: 'KEV actif',
  priorite_score: 'Score de priorité'
}
```

### 7.6 Vue recommandations — Recommandations.vue

La page de recommandations présente cinq catégories de bonnes pratiques de sécurité applicables aux environnements IoT : patching, configuration sécurisée, segmentation réseau, désactivation des services inutiles, et bonnes pratiques générales. Ce contenu est statique et constitue une section d'aide à la décision complémentaire aux données de vulnérabilités.

Les recommandations générales en cybersécurité IoT évoluent peu, et leur intégration statique évite de complexifier inutilement l'architecture.

---

## 8. Limites identifiées et pistes d'amélioration

### 8.1 Limites du backend

**Performances de la collecte historique :**  
Chaque CVE déclenche une requête individuelle vers l'API EPSS. Sur un volume de plusieurs milliers d'entrées, cela peut générer des milliers de requêtes HTTP séquentielles, rendant la collecte initiale très longue (potentiellement plusieurs heures). Une optimisation serait d'utiliser l'endpoint batch de l'API EPSS, qui accepte jusqu'à 2000 CVE IDs en une seule requête :  
`GET https://api.first.org/data/v1/epss?cve=CVE-XXXX,CVE-YYYY,...`

**Absence de gestion CVSS v2 :**  
Les CVE antérieures à 2018 n'ont souvent que des scores CVSS v2. Le code ignore ces scores et stocke `0.0`. Ce choix a été fait en partant du principe que ce site permet surtout de mettre à jour la base, de voir les nouvelles vulnérabilités, c'est son point principal.



### 8.2 Limites de l'interface web

**Absence de filtrage et de tri :** la liste des vulnérabilités ne propose pas de mécanisme de recherche, de filtre par score CVSS ou EPSS, ni de tri par score de priorité. Pour un usage opérationnel, ces fonctionnalités sont indispensables.

**Chargement complet sans pagination :** l'API retourne l'ensemble des CVE en une seule requête. Pour une base contenant plusieurs milliers d'entrées, cela peut entraîner des temps de chargement significatifs et une consommation mémoire côté client importante.

**Recommandations statiques :** la page de recommandations ne propose pas de recommandations contextuelles liées aux CVE affichées. Cela correspond tout de même au demande et à une utilisation dans un cas concret. Une évolution possible serait de générer des recommandations dynamiques selon les CWE les plus fréquentes dans la base.

### 9.3 Pistes d'amélioration prioritaires

Pour une prochaine itération, les améliorations possibles seraient :

1. Ajouter des filtres côté interface (par score, par date, par présence KEV) ;
2. Mettre en place une pagination côté API et côté frontend ;
3. Enrichir les logs avec le module `logging` pour faciliter le suivi opérationnel ;
4. Ajouter la gestion des scores CVSS v2 pour les CVE historiques.

---

## 9. Conclusion

La plateforme de priorisation des vulnérabilités IoT développée dans le cadre de ce projet couvre la chaîne de valeur : de la collecte automatisée des données brutes depuis des sources de référence reconnues, jusqu'à la restitution visuelle dans une interface web ergonomique.

Le pipeline de collecte développé constitue une base pour la plateforme de priorisation des vulnérabilités IoT. Il répond aux exigences fondamentales qui sont la collecte automatisée depuis trois sources open-source reconnues (NVD, CISA KEV, FIRST EPSS), l'enrichissement multi-critères, et la persistance locale dans une base SQLite bien structurée.

La formule de priorisation adoptée aligne la démarche sur les recommandations des organismes de référence en cybersécurité. L'architecture en deux scripts distincts (collecte historique unique et collecte différentielle quotidienne) permet de séparer clairement les phases d'initialisation et de maintenance.

L'interface Vue.js apporte une valeur ajoutée par rapport à une consultation directe de la base de données. En effet, le codage couleur du score de priorité, la navigation entre liste et fiche détaillée, et la page de recommandations offrent une expérience utilisateur adaptée à un public de professionnels ou d'amateurs de la sécurité.
