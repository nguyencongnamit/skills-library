---
id: file-upload-security
language: fr
source_revision: "4c215e6f"
version: "1.0.0"
title: "Sécurité de l'upload de fichiers"
description: "Valider les uploads utilisateur : magic bytes MIME, assainissement de filename, limites de taille, domaine de service séparé, scan AV, détection de polyglottes"
category: prevention
severity: high
applies_to:
  - "lors de la génération d'un endpoint HTTP d'upload de fichier"
  - "lors du câblage d'un upload par URL pré-signée vers S3 / GCS / Azure Blob"
  - "lors de l'ajout de traitement image/PDF/document d'uploads utilisateur"
  - "lors de la revue du stockage et du service de contenu généré par l'utilisateur"
languages: ["*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "ssrf-prevention", "infrastructure-security", "cors-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP File Upload Cheat Sheet"
  - "CWE-434: Unrestricted Upload of File with Dangerous Type"
  - "CWE-22: Path Traversal"
  - "CVE-2018-15473 (libmagic), CVE-2016-3714 (ImageTragick)"
---

# Sécurité de l'upload de fichiers

## Règles (pour les agents IA)

### TOUJOURS
- Vérifier les **magic bytes** de chaque upload côté serveur.
  `Content-Type` et l'extension du fichier sont contrôlés par
  l'attaquant et ne sont jamais suffisants. Utiliser libmagic,
  `file-type` (Node), `mimetypes-magic` (Python) ou Tika.
- Maintenir une **allowlist** de types acceptés par endpoint
  (`image/png`, `image/jpeg`, `application/pdf`, …). Refuser tout le
  reste, y compris `text/html`, `image/svg+xml` (porte `<script>`),
  `text/xml` et `application/octet-stream`.
- Assainir les noms de fichier : retirer les composants de
  répertoire, normaliser l'Unicode, rejeter `..`, l'octet NUL, les
  caractères de contrôle, les noms réservés Windows (`CON`, `PRN`,
  `AUX`, `NUL`, `COM1-9`, `LPT1-9`) et tout caractère hors
  `[a-zA-Z0-9._-]`. Stocker en UUID / hash et conserver le nom
  original dans une colonne de métadonnées séparée et échappée.
- Imposer une **limite de taille** au proxy / API gateway *et* dans
  l'application — au minimum sur deux couches. La limite du proxy
  prévient le DoS de bande passante ; la limite app prévient
  l'épuisement mémoire lorsqu'un proxy est mal configuré.
- Stocker les uploads **hors du document root** et les servir
  depuis un domaine séparé (`usercontent.example.net`) via CDN.
  Définir `Content-Disposition: attachment` pour les types non-image
  et un header `Content-Security-Policy: default-src 'none'; sandbox`
  pour neutraliser tout HTML/SVG rendu inline.
- Lancer un **scanner antivirus** (ClamAV, VirusTotal, Sophos) sur
  chaque upload avant de le rendre accessible à d'autres utilisateurs
  — hors-bande pour que la requête elle-même ne soit pas liée à la
  latence.
- Re-encoder les médias côté serveur : `convert in.jpg out.jpg`
  (ImageMagick avec un `policy.xml` strict), `ffmpeg -i` pour la
  vidéo, `pdftocairo` pour les PDF. Le ré-encodage retire la plupart
  des payloads polyglottes / stéganographiques et des exploits de
  codec exotiques.
- Pour SVG en particulier : soit rendre côté serveur en format
  raster, soit passer par un sanitizer à allowlist stricte
  (DOMPurify en Node, `lxml.html.clean` en Python) qui retire
  `<script>`, `<iframe>`, `<foreignObject>`, `xlink:href` avec
  `javascript:`, et CSS expression / url() avec des URI non-data.

### JAMAIS
- Faire confiance au `Content-Type` du client. Le sniffer MIME d'IE
  / d'anciens Chrome lit le body à la recherche d'indices de type
  — une payload HTML déguisée en `image/png` tournera comme HTML
  servie en same-origin.
- Construire le chemin de stockage avec le filename fourni par
  l'utilisateur. Le path traversal (`../../etc/passwd`) et la classe
  des noms réservés Windows se réduisent tous deux à "laisser
  l'attaquant choisir où écrire".
- Servir les uploads depuis le même origin que l'application. Servir
  sur `api.example.com/uploads/x.html` signifie qu'un upload HTML
  malveillant tourne avec un accès complet aux cookies de
  api.example.com et au CORS.
- Utiliser un stack qui traite les uploads avec ImageMagick / libraw
  / ExifTool / ffmpeg sans policy.xml strict / sandbox / contrôle de
  version. ImageTragick (CVE-2016-3714) et GitLab ExifTool
  (CVE-2021-22205) reposaient tous deux sur un serveur transmettant
  joyeusement des octets contrôlés par l'utilisateur à une
  bibliothèque média.
- Autoriser l'upload PDF + rendu in-browser sans vérifier que le PDF
  passe une validation structurelle (p. ex. `pdfinfo`). Les PDF
  malveillants sont une primitive RCE JavaScript-dans-PDF / XFA
  courante contre Adobe Reader côté destinataire, même quand le
  serveur est sain.
- Utiliser l'extraction `.docx` / `.xlsx` / `.zip` avec `unzip` ou
  `python -m zipfile` sans extracteur sûr contre le path traversal.
  Zip slip (CVE-2018-1002201) a extrait des fichiers hors du
  répertoire cible via des entrées `../`.
- Utiliser des URL pré-signées d'upload S3 / GCS sans condition
  `Content-Type` signée stricte et préfixe d'object-key fixé. Sans
  ces conditions, le client peut uploader n'importe quoi sur
  n'importe quelle clé.

### FAUX POSITIFS CONNUS
- Les uploads admin uniquement internes (p. ex. un dashboard d'ops)
  peuvent légitimement faire confiance à l'extension de fichier car
  la trust boundary est le SSO + allowlist IP. Documenter cela
  comme une décision délibérée dans l'endpoint.
- Certaines intégrations (p. ex. export CSV depuis des outils BI)
  doivent faire un round-trip des filenames fournis par
  l'utilisateur ; les préserver en métadonnées, mais le nom on-disk
  doit rester un UUID.
- Tarballs / DEB / RPM dans un pipeline de build n'ont pas besoin de
  scan AV — la trust boundary est la clé de signature du pipeline
  de build, pas l'AV.

## Contexte (pour les humains)

L'upload de fichiers est la surface d'attaque riche et persistante.
Chaque lab de breach du monde réel inclut un coup d'early-game
"trouver un formulaire d'upload" parce que le chemin de l'upload au
RCE est généralement court : uploader un fichier HTML avec un
voleur de credentials JavaScript, uploader un shell PHP / JSP sur
un doc-root mal configuré, uploader un SVG avec un `<script>`
voleur de SAML, uploader une image au payload EXIF sur un service
ImageMagick vulnérable.

Les défenses sont bien comprises et peu coûteuses — le bug est
qu'elles doivent s'appliquer en combinaison. Une allowlist de
magic bytes est trivialement contournée par un polyglotte (un
fichier qui est simultanément un PNG valide et une page HTML
valide). Un domaine de service séparé neutralise l'exécution HTML
du polyglotte. Un scanner antivirus attrape les malwares connus.
Le ré-encodage retire les payloads de codec bizarres. Chaque défense
est une couche ; en manquer une transforme la plupart des uploads
de "données stockées" en "RCE stocké".

## Références

- `rules/upload_validation.json`
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
- [CWE-434](https://cwe.mitre.org/data/definitions/434.html).
- [CWE-22 (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html).
- [Snyk Zip Slip directory](https://snyk.io/research/zip-slip-vulnerability).
- [ImageTragick (CVE-2016-3714)](https://imagetragick.com/).
