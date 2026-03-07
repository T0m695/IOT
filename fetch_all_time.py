import sqlite3
import requests
import time
from datetime import datetime

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

def recuperer_tout_historique():
    perimetre = "ip camera"
    url_nist = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    url_kev = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    
    try:
        rep_kev = requests.get(url_kev, timeout=15)
        kev_catalog = rep_kev.json().get("vulnerabilities", []) if rep_kev.status_code == 200 else []
        print(f"Catalogue KEV chargé ({len(kev_catalog)} entrées).")

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        index = 0
        total_recupere = 0
        continuer = True

        while continuer:
            params_nist = {
                "keywordSearch": perimetre,
                "startIndex": index,
                "resultsPerPage": 2000  
            }
            
            print(f"Requête NIST : résultats {index} à {index + 2000}...")
            rep_nist = requests.get(url_nist, params=params_nist, timeout=30)
            
            if rep_nist.status_code != 200:
                print(f"Erreur API NIST ({rep_nist.status_code}). Arrêt.")
                break

            data = rep_nist.json()
            vulnerabilites = data.get("vulnerabilities", [])
            
            if not vulnerabilites:
                continuer = False
                break

            for item in vulnerabilites:
                cve_id = item.get("cve", {}).get("id")
                
                
                metrics = item.get("cve", {}).get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
                cvss_score = cvss_v3[0]["cvssData"]["baseScore"] if cvss_v3 else 0.0
                
        
                epss_score = 0.0
                try:
                    res_e = requests.get(f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=5)
                    e_data = res_e.json().get("data", [])
                    epss_score = float(e_data[0].get("epss", 0.0)) if e_data else 0.0
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
                    datetime.now().strftime("%Y-%m-%d")
                ))
                total_recupere += 1

            index += 2000
            conn.commit() 
            
            time.sleep(6) 

        conn.close()
        
    except Exception as e:
        print(f"Erreur durant la récupération globale : {e}")

if __name__ == "__main__":
    initialiser_bdd()
    recuperer_tout_historique()