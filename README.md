# Projet : Consolidation, Enrichissement et Visualisation des Vulnérabilités ANSSI

## Description

Ce projet Jupyter Notebook permet d’automatiser la collecte, l’enrichissement et l’analyse des bulletins de vulnérabilités publiés par l’ANSSI. Il extrait les informations clés, enrichit les données avec des sources externes (CVE, EPSS), consolide le tout dans un fichier CSV, puis propose des visualisations pour l’interprétation et la priorisation des risques.

---

## Fonctionnalités du Notebook

### 1. Récupération des bulletins ANSSI
- Utilisation de la bibliothèque `feedparser` pour lire le flux RSS des bulletins ANSSI.
- Extraction des titres, descriptions, liens et dates de publication.

### 2. Extraction des identifiants CVE
- Pour chaque bulletin, extraction des identifiants CVE référencés via l’URL JSON du bulletin et par recherche avec une expression régulière.

### 3. Enrichissement des vulnérabilités
- Pour chaque CVE trouvé, interrogation de l’API MITRE pour obtenir la description, le score CVSS, la sévérité, le type CWE, les produits affectés, etc.
- Récupération du score EPSS (probabilité d’exploitation) via l’API FIRST.

### 4. Consolidation des données
- Fusion de toutes les informations extraites et enrichies dans un DataFrame pandas.
- Ajout des nouvelles données au fichier `data.csv` sans dupliquer les anciennes entrées.

### 5. Visualisation et interprétation
- Génération de graphiques (histogrammes, camemberts, courbes, nuages de points, etc.) pour analyser la gravité, la fréquence, la probabilité d’exploitation et la répartition des vulnérabilités à partir du fichier `data.csv`.

---

## Fichier `.env` requis

Pour la partie notification ou envoi d’alertes par email (optionnelle), **il faut créer un fichier `.env`** à la racine du projet contenant vos identifiants de messagerie :

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

---

## Utilisation du Notebook

1. **Extraction** : Récupère les bulletins et CVE depuis le flux RSS ANSSI.
2. **Enrichissement** : Pour chaque CVE, récupère les infos détaillées et le score EPSS.
3. **Consolidation** : Fusionne toutes les données dans un CSV, sans doublons.
4. **Visualisation** : Lance les scripts de visualisation pour interpréter les résultats.
5. **Notification** : (optionnel) Envoie des alertes par email selon les critères définis, en utilisant les identifiants du fichier `.env`.

---

## Remarques

- Le projet gère les valeurs manquantes et les champs absents.
- Les visualisations sont adaptables selon vos besoins.
- Le CSV peut être enrichi à chaque exécution sans doublons.
- Toutes les étapes sont réalisées dans le notebook, étape par étape, pour faciliter la compréhension et la personnalisation. 