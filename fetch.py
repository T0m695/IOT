import requests
from datetime import datetime, timedelta

def collecter_donnees_iot():
    perimetre = "ip camera" 
    
    # permet à l'automatisation d'aller chercher directement la veille
    hier = datetime.now() - timedelta(days=1)
    date_str = hier.strftime("%Y-%m-%d")
    
    # stockage que vous allez remplacer par la BDD (on avait dit sqlite je crois) 
    base_de_donnees_temporaire = []

    print(f"Les {perimetre} du {date_str}")

    #  NIST 
    url_nist = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params_nist = {
        "keywordSearch": perimetre,
        "lastModStartDate": f"{date_str}T00:00:00.000Z",# on cherche pour la veille, donc de 0h à 23h59
        "lastModEndDate": f"{date_str}T23:59:59.999Z"
    }

    try:
        reponse_nist = requests.get(url_nist, params=params_nist, timeout=20)
        reponse_nist.raise_for_status()
        vulnerabilites = reponse_nist.json().get("vulnerabilities", [])

        # catalogue
        url_kev = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        reponse_kev = requests.get(url_kev, timeout=15)
        kev_catalog = reponse_kev.json().get("vulnerabilities", []) if reponse_kev.status_code == 200 else []

        for item in vulnerabilites:
            cve_item = item.get("cve", {})
            cve_id = cve_item.get("id")

            
            metrics = cve_item.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
            cvss_score = cvss_v3[0]["cvssData"]["baseScore"] if cvss_v3 else 0.0

            # extraction EPSS 
            epss_score = 0.0
            try:
                url_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
                reponse_epss = requests.get(url_epss, timeout=10)
                if reponse_epss.status_code == 200:
                    data_epss = reponse_epss.json().get("data", [])
                    if data_epss:
                        epss_score = float(data_epss[0].get("epss", 0.0))
            except Exception:
                pass 

            # extraction KEV
            # on vérifie si l'ID de la CVE actuelle est présent dans le catalogue KEV
            est_dans_kev = any(v.get("cveID") == cve_id for v in kev_catalog)

            
            donnees_enrichies = {
                "cve_id": cve_id,
                "description": cve_item.get("descriptions", [{}])[0].get("value", "N/A"),
                "cvss_impact": cvss_score,      # Impact (NIST) [cite: 29]
                "epss_prob": epss_score,        # Probabilité (EPSS) [cite: 33]
                "kev_actif": est_dans_kev,      # Exploitation réelle (CISA) [cite: 31]
                "cwe": [w.get("description", [{}])[0].get("value") for w in cve_item.get("weaknesses", [])], # [cite: 36]
                "date_collecte": date_str
            }
            
            base_de_donnees_temporaire.append(donnees_enrichies)
            print(f"{cve_id} | CVSS: {cvss_score} | EPSS: {epss_score} | KEV: {est_dans_kev}")

    except Exception as e:
        print(f"Erreur : {e}")

    return base_de_donnees_temporaire

if __name__ == "__main__":
    # à changer et rajouter le fait de l'ajouter dans la base de données
    resultats = collecter_donnees_iot()
    print(f"\n Fin : {len(resultats)} vulnérabilités")