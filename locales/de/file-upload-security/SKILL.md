---
id: file-upload-security
language: de
source_revision: "4c215e6f"
version: "1.0.0"
title: "File-Upload-Sicherheit"
description: "User-Uploads validieren: MIME-Magic-Bytes, Filename-Sanitisierung, Grössenlimits, separate Serving-Domain, AV-Scan, Polyglot-Erkennung"
category: prevention
severity: high
applies_to:
  - "beim Erzeugen eines HTTP-File-Upload-Endpoints"
  - "beim Verdrahten von Presigned-URL-Upload zu S3 / GCS / Azure Blob"
  - "beim Hinzufügen von Bild- / PDF- / Dokumenten-Verarbeitung von User-Uploads"
  - "beim Review von User-Generated-Content-Storage und -Serving"
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

# File-Upload-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- Die **Magic Bytes** jedes Uploads serverseitig verifizieren.
  `Content-Type` und Dateiendung sind angreiferkontrolliert und nie
  ausreichend. libmagic, `file-type` (Node), `mimetypes-magic`
  (Python) oder Tika verwenden.
- Eine **Allowlist** akzeptierter Typen pro Endpoint pflegen
  (`image/png`, `image/jpeg`, `application/pdf`, …). Alles andere
  ablehnen, einschliesslich `text/html`, `image/svg+xml` (trägt
  `<script>`), `text/xml` und `application/octet-stream`.
- Dateinamen sanitisieren: Verzeichniskomponenten entfernen, Unicode
  normalisieren, `..`, NUL-Byte, Steuerzeichen, reservierte Windows-
  Namen (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) und alle
  nicht-`[a-zA-Z0-9._-]`-Zeichen ablehnen. Als UUID / Hash speichern
  und den Original-Filename in einer separaten, escapeten
  Metadaten-Column halten.
- Ein **Grössenlimit** am Proxy / API-Gateway *und* in der
  Anwendung erzwingen — mindestens doppellagig. Das Proxy-Limit
  verhindert Bandwidth-DoS; das App-Limit verhindert
  Speicher-Erschöpfung, wenn ein Proxy fehlkonfiguriert ist.
- Uploads **ausserhalb des Document-Roots** speichern und von einer
  separaten Domain (`usercontent.example.net`) über ein CDN ausliefern.
  `Content-Disposition: attachment` für Nicht-Bild-Typen setzen und
  einen `Content-Security-Policy: default-src 'none'; sandbox`-
  Header, um jegliches inline gerendertes HTML/SVG zu neutralisieren.
- Einen **Virenscanner** (ClamAV, VirusTotal, Sophos) auf jeden
  Upload laufen lassen, bevor er anderen Usern zugänglich gemacht
  wird — out-of-band, damit der Request selbst nicht latenzgebunden
  ist.
- Medien serverseitig re-encodieren: `convert in.jpg out.jpg`
  (ImageMagick mit striktem `policy.xml`), `ffmpeg -i` für Video,
  `pdftocairo` für PDFs. Re-Encodieren entfernt die meisten Polyglot-
  / steganographischen Payloads und exotischen Codec-Exploits.
- Speziell für SVG: entweder serverseitig in ein Rasterformat
  rendern oder durch einen strikten Allowlist-Sanitizer (DOMPurify
  in Node, `lxml.html.clean` in Python) leiten, der `<script>`,
  `<iframe>`, `<foreignObject>`, `xlink:href` mit `javascript:` und
  CSS-Expression / `url()` mit Nicht-Data-URIs entfernt.

### NIE
- Dem `Content-Type` vom Client vertrauen. Der MIME-Sniffer in IE /
  älterem Chrome liest den Body nach Type-Hinweisen — eine als
  `image/png` getarnte HTML-Payload läuft als HTML, wenn sie
  same-origin ausgeliefert wird.
- Den Storage-Pfad mit dem user-gelieferten Filename konstruieren.
  Path-Traversal (`../../etc/passwd`) und die Windows-Reserved-Name-
  Klasse reduzieren sich beide auf "lass den Angreifer wählen, wo
  geschrieben wird".
- Uploads vom selben Origin wie die Anwendung ausliefern. Auslieferung
  auf `api.example.com/uploads/x.html` bedeutet, ein bösartiger HTML-
  Upload läuft mit vollem Zugriff auf api.example.com-Cookies und
  CORS.
- Einen Stack verwenden, der Uploads mit ImageMagick / libraw /
  ExifTool / ffmpeg ohne striktes policy.xml / Sandbox / Versions-
  Kontrolle verarbeitet. ImageTragick (CVE-2016-3714) und GitLab
  ExifTool (CVE-2021-22205) basierten beide darauf, dass ein Server
  user-kontrollierte Bytes fröhlich an eine Media-Library
  weiterreichte.
- PDF-Upload + In-Browser-Render zulassen, ohne zu verifizieren, dass
  das PDF die strukturelle Validierung besteht (z. B. `pdfinfo`).
  Bösartige PDFs sind ein gängiges JavaScript-in-PDF- / XFA-RCE-
  Primitiv gegen Adobe Reader auf der Empfängerseite, selbst wenn
  der Server sicher ist.
- `.docx` / `.xlsx` / `.zip`-Extraktion mit `unzip` oder
  `python -m zipfile` ohne Path-Traversal-sicheren Extractor
  verwenden. Zip-Slip (CVE-2018-1002201) hat Dateien über `../`-
  Einträge ausserhalb des Zielverzeichnisses extrahiert.
- S3- / GCS-Presigned-Upload-URLs ohne strikte signierte
  `Content-Type`-Condition und festes Object-Key-Prefix verwenden.
  Ohne die Conditions kann der Client beliebige Inhalte an
  beliebige Keys hochladen.

### BEKANNTE FALSCH-POSITIVE
- Nur-interne Admin-Uploads (z. B. ein Ops-Dashboard) dürfen
  legitim der Dateiendung vertrauen, weil die Trust-Boundary
  SSO + IP-Allowlist ist. Das als bewusste Entscheidung im Endpoint
  dokumentieren.
- Manche Integrationen (z. B. CSV-Export aus BI-Tools) müssen
  user-gelieferte Filenames roundtrippen; sie in Metadaten erhalten,
  aber der On-Disk-Name muss trotzdem eine UUID sein.
- Tarballs / DEBs / RPMs in einer Build-Pipeline brauchen keinen AV-
  Scan — die Trust-Boundary ist der Signing-Key der Build-Pipeline,
  nicht der AV.

## Kontext (für Menschen)

File-Upload ist die persistente, lohnende Angriffsfläche. Jedes
reale Breach-Lab enthält im Early-Game den Zug "find an upload form",
weil der Weg von Upload zu RCE meist kurz ist: ein HTML-File mit
JavaScript-Credential-Stealer hochladen, eine PHP- / JSP-Shell in
einen fehlkonfigurierten Doc-Root hochladen, ein SVG mit einem
SAML-Stealer-`<script>` hochladen, ein EXIF-payload-Bild auf einen
verwundbaren ImageMagick-Service hochladen.

Die Verteidigungen sind gut verstanden und billig — der Bug ist,
dass sie kombiniert angewandt werden müssen. Eine Magic-Byte-
Allowlist wird trivial durch ein Polyglot umgangen (eine Datei, die
gleichzeitig ein gültiges PNG und eine gültige HTML-Seite ist).
Eine separate Serving-Domain neutralisiert die HTML-Ausführung des
Polyglots. Ein Virenscanner fängt bekannte Malware. Re-Encodieren
entfernt exotische Codec-Payloads. Jede Verteidigung ist eine
Schicht; fehlt eine, kippt der meiste Upload von "gespeicherten
Daten" zu "gespeichertem RCE".

## Referenzen

- `rules/upload_validation.json`
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
- [CWE-434](https://cwe.mitre.org/data/definitions/434.html).
- [CWE-22 (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html).
- [Snyk Zip Slip directory](https://snyk.io/research/zip-slip-vulnerability).
- [ImageTragick (CVE-2016-3714)](https://imagetragick.com/).
