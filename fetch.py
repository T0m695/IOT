import sqlite3
import requests
from datetime import datetime, timedelta

DB_NAME = "vulnerabilites_iot.db"

def initialiser_bdd():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vuln_iot (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            cvss_impact REAL,
            epss_prob REAL,
            kev_actif INTEGER,
            cwe TEXT,
            priorite_score REAL,
            date_collecte TEXT
        )
    ''')
    conn.commit()
    conn.close()

def executer_collecte_complete():
    perimetre = "ip camera" 
    # permet à l'automatisation d'aller chercher directement la veille
    hier = datetime.now() - timedelta(days=1)
    date_str = hier.strftime("%Y-%m-%d")

    
    url_nist = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    url_kev = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    try:
        
        rep_kev = requests.get(url_kev, timeout=15)
        kev_catalog = rep_kev.json().get("vulnerabilities", []) if rep_kev.status_code == 200 else []
        
        
        params_nist = {
            "keywordSearch": perimetre,
            "lastModStartDate": f"{date_str}T00:00:00.000Z",
            "lastModEndDate": f"{date_str}T23:59:59.999Z"
        }
        rep_nist = requests.get(url_nist, params=params_nist, timeout=20)
        vulnerabilites = rep_nist.json().get("vulnerabilities", [])

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        for item in vulnerabilites:
            cve_id = item.get("cve", {}).get("id")
            
            # scores 
            metrics = item.get("cve", {}).get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
            cvss_score = cvss_v3[0]["cvssData"]["baseScore"] if cvss_v3 else 0.0
            epss_score = 0.0
            try:
                res_e = requests.get(f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=5)
                data = res_e.json().get("data", [])
                epss_score = float(data[0].get("epss", 0.0)) if data else 0.0
            except: pass

           
            est_dans_kev = 1 if any(v.get("cveID") == cve_id for v in kev_catalog) else 0

            priorite = (cvss_score * 0.5) + (epss_score * 10) + (est_dans_kev * 3.0)

            
            cursor.execute('''
                INSERT OR REPLACE INTO vuln_iot 
                (cve_id, description, cvss_impact, epss_prob, kev_actif, cwe, priorite_score, date_collecte)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_id,
                item.get("cve", {}).get("descriptions", [{}])[0].get("value", "N/A"),
                cvss_score,
                epss_score,
                est_dans_kev,
                str([w.get("description", [{}])[0].get("value") for w in item.get("cve", {}).get("weaknesses", [])]),
                round(priorite, 2),
                date_str
            ))
        
        conn.commit()
        conn.close()
        print(f"Base de données mise à jour : {len(vulnerabilites)} CVE traitées.")

    except Exception as e:
        print(f"Erreur durant le processus : {e}")

if __name__ == "__main__":
    initialiser_bdd()
    executer_collecte_complete()
