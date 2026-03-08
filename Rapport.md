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

Ce script a pour but d'effectuer une **collecte initiale exhaustive** de toutes les CVE référencées dans la base NVD pour les mots-clé `"ip camera"`, `"network camera"`, `"NVR"`, `"ONVIF"`, `"Hikvision"`. Avoir tout ces mots permet d'avoir plus de résultat, plutôt que de n'avoir que les résultats plus restreint avec `"ip camera"`. Il s'exécute une seule fois lors du déploiement et peut prendre plusieurs minutes selon le volume de données. La structure permet de remplacer ces mots par le modèle exacte d'une caméra si nécessaire.

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

## 7. Limites identifiées et pistes d'amélioration

### 7.1 Limites techniques actuelles

**Performances de la collecte historique :**  
Chaque CVE déclenche une requête individuelle vers l'API EPSS. Sur un volume de plusieurs milliers d'entrées, cela peut générer des milliers de requêtes HTTP séquentielles, rendant la collecte initiale très longue (potentiellement plusieurs heures). Une optimisation serait d'utiliser l'endpoint batch de l'API EPSS, qui accepte jusqu'à 2000 CVE IDs en une seule requête :  
`GET https://api.first.org/data/v1/epss?cve=CVE-XXXX,CVE-YYYY,...`

**Absence de gestion CVSS v2 :**  
Les CVE antérieures à 2018 n'ont souvent que des scores CVSS v2. Le code ignore ces scores et stocke `0.0`, ce qui fausse artificiellement la priorité de vulnérabilités pourtant sévères. Ce choix a été fait en partant du principe que ce site permet surtout de mettre à jour la base, de voir les nouvelles vulnérabilités, c'est son point principal.



## 9. Conclusion

Le pipeline de collecte développé constitue une base solide et fonctionnelle pour la plateforme de priorisation des vulnérabilités IoT. Il répond aux exigences fondamentales du MVP : collecte automatisée depuis trois sources open-source reconnues (NVD, CISA KEV, FIRST EPSS), enrichissement multi-critères, et persistance locale dans une base SQLite bien structurée.

La formule de priorisation adoptée est justifiée et aligne la démarche sur les recommandations des organismes de référence en cybersécurité. L'architecture en deux scripts distincts — collecte historique unique et collecte différentielle quotidienne — est une décision de conception pertinente qui sépare clairement les phases d'initialisation et de maintenance.
