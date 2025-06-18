# Projet : Consolidation, Enrichissement et Visualisation des Vulnérabilités ANSSI

## Description

Ce projet automatise la collecte, l’enrichissement et l’analyse des bulletins de vulnérabilités publiés par l’ANSSI. Il extrait les informations clés, enrichit les données avec des sources externes (CVE, EPSS), consolide le tout dans un fichier CSV, puis propose des visualisations pour l’interprétation et la priorisation des risques.

---

## Fonctions principales

### 1. `recuperer_bulletins_rss(url)`
Récupère tous les bulletins ANSSI depuis un flux RSS.

### 2. `recuperer_nouveaux_bulletins(url, anciens_liens)`
Récupère uniquement les bulletins dont le lien n’est pas déjà connu.

### 3. `recuperer_bulletins_apres_date(url, date_limite)`
Récupère les bulletins publiés après une date donnée (prend en compte heure/minute/seconde).

### 4. `extraire_cves_depuis_bulletin(lien_bulletin)`
Extrait tous les identifiants CVE référencés dans un bulletin ANSSI (via son URL JSON).

### 5. `extraire_infos_cve(cve_ids)`
Pour chaque CVE, récupère la description, le score CVSS, la sévérité, le type CWE, les produits affectés, etc.

### 6. `extraire_epss_pour_cves(cve_ids)`
Récupère le score EPSS (probabilité d’exploitation) pour chaque CVE.

### 7. Consolidation des données
Fusionne toutes les informations extraites et enrichies dans un DataFrame puis un CSV.

### 8. Visualisation et interprétation
Génère des graphiques (histogrammes, camemberts, courbes, heatmaps, etc.) pour analyser et prioriser les vulnérabilités.

---

## Fichier `.env` requis

Pour la partie notification ou envoi d’alertes par email, **il faut créer un fichier `.env`** à la racine du projet contenant vos identifiants de messagerie :

```
EMAIL=ton.email@exemple.com
MDP=ton_mot_de_passe
```

Ces informations sont utilisées pour sécuriser l’envoi d’emails sans exposer vos identifiants dans le code source.

---

## Définitions des termes techniques

- **ANSSI** : Agence nationale de la sécurité des systèmes d'information (France).
- **Bulletin ANSSI** : Avis ou alerte publié par l’ANSSI concernant une vulnérabilité.
- **CVE** : Common Vulnerabilities and Exposures, identifiant unique d’une vulnérabilité.
- **CVSS** : Common Vulnerability Scoring System, score de gravité d’une vulnérabilité (de 0 à 10).
- **Base Severity** : Niveau de gravité associé au score CVSS (Critique, Élevée, Moyenne, Faible).
- **CWE** : Common Weakness Enumeration, catégorie de la vulnérabilité (ex : CWE-79 = XSS).
- **EPSS** : Exploit Prediction Scoring System, **score qui estime la probabilité qu’une vulnérabilité soit exploitée dans les 30 prochains jours**. Plus le score EPSS est élevé (proche de 1), plus la vulnérabilité a de chances d’être exploitée rapidement.
- **DataFrame** : Structure de données tabulaire de la bibliothèque pandas.
- **Regex** : Expression régulière, utilisée pour extraire des motifs dans du texte.
- **Heatmap** : Carte de chaleur, graphique montrant la densité ou la corrélation entre deux variables.
- **Boxplot** : Diagramme en boîte, visualise la dispersion d’une variable.
- **Nuage de points** : Scatter plot, visualise la relation entre deux variables numériques.

---

## Utilisation

1. **Extraction** : Récupère les bulletins et CVE depuis le flux RSS ANSSI.
2. **Enrichissement** : Pour chaque CVE, récupère les infos détaillées et le score EPSS.
3. **Consolidation** : Fusionne toutes les données dans un CSV.
4. **Visualisation** : Lance les scripts de visualisation pour interpréter les résultats.
5. **Notification** : (optionnel) Envoie des alertes par email selon les critères définis, en utilisant les identifiants du fichier `.env`.

---

## Remarques

- Le projet gère les valeurs manquantes et les champs absents.
- Les visualisations sont adaptables selon vos besoins.
- Le CSV peut être enrichi à chaque exécution sans doublons.

---