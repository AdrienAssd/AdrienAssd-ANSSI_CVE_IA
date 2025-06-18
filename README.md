# Projet : Consolidation, Enrichissement et Visualisation des Vulnérabilités ANSSI

## Description

Ce projet automatise la collecte, l’enrichissement et l’analyse des bulletins de vulnérabilités publiés par l’ANSSI. Il extrait les informations clés, enrichit les données avec des sources externes (CVE, EPSS), consolide le tout dans un fichier CSV, puis propose des visualisations pour l’interprétation et la priorisation des risques.

---

## Fonctionnalités principales

- **Collecte automatique des bulletins ANSSI**  
  Le script récupère les nouveaux bulletins publiés sur le site de l’ANSSI via le flux RSS, en ne traitant que ceux qui sont plus récents que la dernière entrée du fichier CSV.

- **Extraction des identifiants CVE**  
  Pour chaque bulletin, le script extrait les identifiants CVE associés, soit via le JSON du bulletin, soit par recherche dans le texte.

- **Enrichissement des vulnérabilités**  
  Pour chaque CVE trouvé, le script interroge l’API MITRE pour obtenir la description, le score CVSS, la sévérité, le type CWE, les produits affectés, etc. Il interroge aussi l’API EPSS pour obtenir la probabilité d’exploitation.

- **Consolidation des données**  
  Toutes les informations extraites et enrichies sont fusionnées dans un tableau (DataFrame pandas) puis sauvegardées dans un fichier CSV, sans doublons.

- **Gestion des valeurs manquantes**  
  Les champs non disponibles sont remplacés par la mention "de type valeur manquante" pour faciliter l’analyse.

- **Visualisation et interprétation**  
  Le script propose des exemples de visualisations (histogrammes, camemberts, courbes, nuages de points, etc.) pour analyser la gravité, la fréquence, la probabilité d’exploitation et la répartition des vulnérabilités.

- **Notification par email (optionnel)**  
  Le projet peut envoyer des alertes par email selon des critères définis, en utilisant les identifiants stockés dans un fichier `.env` (voir ci-dessous).

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