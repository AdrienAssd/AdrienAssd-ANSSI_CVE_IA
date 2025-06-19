# Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

# faire "pip install feedparser" si besoin dans le terminal 
import feedparser
import pandas as pd
from urllib.parse import urlparse
import numpy as np
import requests
import re
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os

## Étape 1 : Extraction des Flux RSS
def extraire_type_et_id_depuis_url(url):
    path_parts = urlparse(url).path.strip("/").split("/")
    type_bulletin = path_parts[-2] if len(path_parts) >= 2 else None
    id_bulletin = path_parts[-1] if len(path_parts) >= 1 else None
    return type_bulletin, id_bulletin

def recuperer_bulletins_rss(url):
    response = requests.get(url)
    rss_feed = feedparser.parse(response.text)
    print(f"URL: {url}")
    print(f"Nombre d'entrées: {len(rss_feed.entries)}")
    bulletins = []
    for entry in rss_feed.entries:
        print(f"Entry: {entry}")
        type_bulletin, id_bulletin = extraire_type_et_id_depuis_url(entry.link)
        bulletin = {
            "ID du bulletin (ANSSI)": id_bulletin,
            "Titre du bulletin (ANSSI)": entry.title,
            "Description": entry.description,
            "Lien du bulletin (ANSSI)": entry.link,
            "Date de publication": entry.published,
            "Type de bulletin": type_bulletin
        }
        bulletins.append(bulletin)
    return bulletins
    
## Étape 2 : Extraction des CVE
def extraire_cves_depuis_bulletin(lien_bulletin):
    # Construit l'URL JSON à partir du lien du bulletin
    if not lien_bulletin.endswith('/'):
        lien_bulletin += '/'
    url_json = lien_bulletin + "json/"
    response = requests.get(url_json)
    data = response.json()
    # Extraction des CVE référencés dans la clé "cves"
    ref_cves = [cve.get("name") for cve in data.get("cves", [])]
    #attention il s’agit d’une liste des dictionnaires avec name et url comme clés
    print( "CVE référencés ", ref_cves)
    # Extraction des CVE avec une regex
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_list = list(set(re.findall(cve_pattern, str(data))))
    print("CVE trouvés :", cve_list)
    return ref_cves, cve_list

## Étape 3 : Enrichissement des CVE
### Exemple de connexion à l'API CVE :
def extraire_infos_cve(cve_ids):
    resultats = []

    for cve_id in cve_ids:
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()

            # Description
            description = (
                data.get("containers", {})
                    .get("cna", {})
                    .get("descriptions", [{}])[0]
                    .get("value", np.nan)
            )

            # Score CVSS et Base Severity via regex
            cvss_score = np.nan
            base_severity = np.nan
            metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])
            for metric in metrics:
                for key in metric.keys():
                    if re.match(r'cvss[vV]?\d*[_]?\d*', key):  # ex: cvssV3_1, cvss3_0, cvssv2
                        score = metric[key].get("baseScore")
                        severity = metric[key].get("baseSeverity", np.nan)
                        if score is not None:
                            cvss_score = score
                        if severity is not None:
                            base_severity = severity
                        break
                if not pd.isna(cvss_score) or not pd.isna(base_severity):
                    break

            # CWE
            cwe = np.nan
            cwe_desc = np.nan
            problemtype = data.get("containers", {}).get("cna", {}).get("problemTypes", [])
            if problemtype:
                descriptions = problemtype[0].get("descriptions", [])
                if descriptions:
                    cwe = descriptions[0].get("cweId", np.nan)
                    cwe_desc = descriptions[0].get("description", np.nan)

            # Produits affectés
            produits = []
            for product in data.get("containers", {}).get("cna", {}).get("affected", []):
                vendor = product.get("vendor", np.nan)
                product_name = product.get("product", np.nan)
                versions = [
                    v.get("version", np.nan)
                    for v in product.get("versions", [])
                    if v.get("status") == "affected"
                ]
                produits.append({
                    "Éditeur": vendor,
                    "Produit": product_name,
                    "Versions": versions
                })

            # Affichage direct
            print(f"CVE : {cve_id}")
            print(f"Description : {description}")
            print(f"Score CVSS : {cvss_score}")
            print(f"Base Severity : {base_severity}")
            print(f"Type CWE : {cwe}")
            print(f"CWE Description : {cwe_desc}")
            for produit in produits:
                print(f"Éditeur : {produit['Éditeur']}, Produit : {produit['Produit']}, Versions : {', '.join(map(str, produit['Versions']))}")
            print("-" * 40)

            # Stockage des résultats
            resultats.append({
                "CVE": cve_id,
                "Description": description,
                "Score CVSS": cvss_score,
                "Base Severity": base_severity,
                "Type CWE": cwe,
                "CWE Description": cwe_desc,
                "Produits affectés": produits
            })

        except Exception as e:
            print(f"[Erreur] {cve_id} : {e}")

    return resultats

### Exemple de connexion à l’API EPSS:
def extraire_epss_pour_cves(cve_ids):
    epss_scores = {}
    for cve_id in cve_ids:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        try:
            response = requests.get(url)
            data = response.json()
            epss_data = data.get("data", [])
            if epss_data:
                epss_score = epss_data[0].get("epss", np.nan)
                epss_scores[cve_id] = epss_score
                print(f"CVE : {cve_id}")
                print(f"Score EPSS : {epss_score}")
            else:
                epss_scores[cve_id] = np.nan
                print(f"Aucun score EPSS trouvé pour {cve_id}")
        except Exception as e:
            epss_scores[cve_id] = np.nan
            print(f"Erreur pour {cve_id} : {e}")
    return epss_scores

# Remplissage des données manquantes et normalisation des scores dans data_complet.csv
# Chargement
df = pd.read_csv("data.csv", sep=";")

# Colonnes
score_cvss_col = "Score CVSS"
score_epss_col = "Score EPSS"
severity_col = "Base Severity"
product_col = "Produit"

# Nettoyage : conversion et remplacement des valeurs manquantes
df[score_cvss_col] = pd.to_numeric(df[score_cvss_col], errors='coerce')
df[score_epss_col] = pd.to_numeric(df[score_epss_col], errors='coerce')
df[severity_col] = df[severity_col].replace(['', 'nan', 'NaN'], np.nan)

# Normalisation du score EPSS
epss_min = df[score_epss_col].min()
epss_max = df[score_epss_col].max()
df["EPSS normalisé"] = (df[score_epss_col] - epss_min) / (epss_max - epss_min)

# Arrondi pour groupement
df["EPSS arrondi"] = df["EPSS normalisé"].round(4)

# Fonction mode avec fallback
def mode_or_nan(series):
    m = series.mode()
    return m.iloc[0] if not m.empty else np.nan

# Moyennes par groupe (Produit + EPSS arrondi)
grouped = df.groupby([product_col, "EPSS arrondi"])
mean_cvss = grouped[score_cvss_col].mean()

# Moyenne globale
global_mean_cvss = df[score_cvss_col].mean()

# Fonction pour déterminer la base severity à partir du score CVSS
def get_base_severity(score):
    if pd.isna(score):
        return "de type valeur manquante"
    if 9 <= score <= 10:
        return "CRITICAL"
    elif 7 <= score < 9:
        return "HIGH"
    elif 4 <= score < 7:
        return "MEDIUM"
    elif 0 <= score < 4:
        return "LOW"
    else:
        return "de type valeur manquante"

# Fonction d’imputation (sans la partie Base Severity par mode, mais avec get_base_severity)
def impute_row(row):
    product = row[product_col]
    epss_rounded = round(row["EPSS normalisé"], 4) if not pd.isna(row["EPSS normalisé"]) else np.nan

    # Score CVSS
    if pd.isna(row[score_cvss_col]):
        if (product, epss_rounded) in mean_cvss.index and not pd.isna(mean_cvss.loc[(product, epss_rounded)]):
            row[score_cvss_col] = round(mean_cvss.loc[(product, epss_rounded)], 2)
        else:
            row[score_cvss_col] = round(global_mean_cvss, 2)

    # Base Severity par règle sur le score CVSS
    if pd.isna(row[severity_col]):
        row[severity_col] = get_base_severity(row[score_cvss_col])

    return row

# Application de l’imputation
df_imputed = df.apply(impute_row, axis=1)

# Affichage des valeurs manquantes restantes
print("Valeurs manquantes après imputation :")
print(df_imputed[[score_cvss_col, severity_col]].isna().sum())

# Sauvegarde
df_imputed.drop(columns=["EPSS normalisé", "EPSS arrondi"]).to_csv("data_complet.csv", sep=";", index=False)
print("Imputation terminée, sauvegardée dans 'data_complet.csv'.")


## Étape 7 : Génération d'Alertes et Notifications Email
# Charger les variables d'environnement
load_dotenv()
from_email = os.getenv("EMAIL_ADDRESS")
password = os.getenv("EMAIL_PASSWORD")

# Fonction d'envoi d'email
def send_email(to_email, subject, body):
    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    try:
        server = smtplib.SMTP('smtp.office365.com', 587)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print(f"✅ Email envoyé à {to_email}.")
    except Exception as e:
        print(f"❌ Erreur lors de l'envoi de l'email : {e}")

# 1. Charger les données
df = pd.read_csv("data_complet.csv", sep=";")

# 2. Définir les critères
# Exemples : criticité = 'Critical', système = 'Linux'
CRITICITE_VISEE = "Critical"
SYSTEME_VISE = "GitLab"  # Recherché dans Éditeur/Vendor ou Produit

# 3. Filtrage des vulnérabilités critiques liées à Linux
df_filtered = df[
    (df['Base Severity'].str.strip().str.lower() == CRITICITE_VISEE.lower()) &
    (
        df['Produit'].str.contains(SYSTEME_VISE, case=False, na=False) |
        df['Éditeur/Vendor'].str.contains(SYSTEME_VISE, case=False, na=False)
    )
]


def main():
    # URLs RSS
    avis_url = "https://www.cert.ssi.gouv.fr/avis/feed/"
    alerte_url = "https://www.cert.ssi.gouv.fr/alerte/feed/"

    # Récupération des données
    avis_bulletins = recuperer_bulletins_rss(avis_url)
    alerte_bulletins = recuperer_bulletins_rss(alerte_url)

    # Fusion
    bulletins = avis_bulletins + alerte_bulletins
    print(bulletins)

    # Afficher les bulletins pour vérification
    for bulletin in bulletins:
        print(bulletin)
    
    tous_les_cves = set()
    for bulletin in bulletins:
        ref_cves, cve_list = extraire_cves_depuis_bulletin(bulletin['Lien du bulletin (ANSSI)'])
        tous_les_cves.update(ref_cves)
        tous_les_cves.update(cve_list)
        bulletin["CVEs"] = list(set(ref_cves + cve_list))
        print(f"Bulletin {bulletin['Titre du bulletin (ANSSI)']} : CVEs = {bulletin['CVEs']}")

    infos_cve = extraire_infos_cve(tous_les_cves)

    # Utilisation
    epss_scores = extraire_epss_pour_cves(tous_les_cves)
    
    ## Étape 4 : Consolidation des Données
    infos_cve_dict = {info["CVE"]: info for info in infos_cve}

    donnees = []
    for bulletin in bulletins:
        cves_bulletin = bulletin.get("CVEs", [])
        if not cves_bulletin:
            # ligne par défaut avec np.nan pour valeurs manquantes
            donnees.append({
                "ID du bulletin (ANSSI)": bulletin.get("ID du bulletin (ANSSI)", ""),
                "Titre du bulletin (ANSSI)": bulletin.get("Titre du bulletin (ANSSI)", ""),
                "Type de bulletin": bulletin.get("Type de bulletin", ""),
                "Date de publication": bulletin.get("Date de publication", ""),
                "Identifiant CVE": np.nan,
                "Score CVSS": np.nan,
                "Base Severity": np.nan,
                "Type CWE": np.nan,
                "Score EPSS": np.nan,
                "Lien du bulletin (ANSSI)": bulletin.get("Lien du bulletin (ANSSI)", ""),
                "Description": bulletin.get("Description", ""),
                "Éditeur/Vendor": np.nan,
                "Produit": np.nan,
                "Versions affectées": np.nan
            })
        else:
            for cve in cves_bulletin:
                info = infos_cve_dict.get(cve, {})
                produits = info.get("Produits affectés", [{}])
                produit = produits[0] if produits else {}
                donnees.append({
                    "ID du bulletin (ANSSI)": bulletin.get("ID du bulletin (ANSSI)", ""),
                    "Titre du bulletin (ANSSI)": bulletin.get("Titre du bulletin (ANSSI)", ""),
                    "Type de bulletin": bulletin.get("Type de bulletin", ""),
                    "Date de publication": bulletin.get("Date de publication", ""),
                    "Identifiant CVE": cve,
                    "Score CVSS": info.get("Score CVSS") if info.get("Score CVSS") is not None else np.nan,
                    "Base Severity": info.get("Base Severity") if info.get("Base Severity") is not None else np.nan,
                    "Type CWE": info.get("Type CWE") if info.get("Type CWE") else np.nan,
                    "Score EPSS": epss_scores.get(cve) if epss_scores.get(cve) is not None else np.nan,
                    "Lien du bulletin (ANSSI)": bulletin.get("Lien du bulletin (ANSSI)", ""),
                    "Description": info.get("Description", bulletin.get("Description", "")),
                    "Éditeur/Vendor": produit.get("Éditeur") if produit.get("Éditeur") else np.nan,
                    "Produit": produit.get("Produit") if produit.get("Produit") else np.nan,
                    "Versions affectées": ", ".join(produit.get("Versions", [])) if produit.get("Versions") else np.nan
                })

    df = pd.DataFrame(donnees)
    
    # Afficher nombre de valeurs manquantes par colonne
    nb_valeurs_manquantes = df.isna().sum()
    print(nb_valeurs_manquantes)

    df.to_csv("data.csv", index=False, encoding='utf-8', sep=';')
    
    
    # 4. Envoi d’un mail pour chaque menace filtrée
    for _, row in df_filtered.iterrows():
        titre = row['Titre du bulletin (ANSSI)']
        produit = row['Produit']
        score_cvss = row['Score CVSS']
        score_epss = row['Score EPSS']
        lien = row['Lien du bulletin (ANSSI)']
        date = row['Date de publication']

    body = (
        f"🚨 Alerte de sécurité critique ({CRITICITE_VISEE}) détectée 🚨\n\n"
        f"📝 Titre : {titre}\n"
        f"📅 Date : {date}\n"
        f"💻 Produit concerné : {produit}\n"
        f"📊 Score CVSS : {score_cvss}\n"
        f"📈 Score EPSS : {score_epss}\n"
        f"🔗 Lien ANSSI : {lien}\n\n"
        f"Veuillez appliquer un correctif dès que possible."
    )

    send_email(
        "test@test.com",  # à personnaliser
        f"[ALERTE] {produit} - {CRITICITE_VISEE} vulnérabilité",
        body
    )
    

if __name__ == "__main__":
    main()
 