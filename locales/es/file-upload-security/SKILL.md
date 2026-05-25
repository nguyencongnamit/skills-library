---
id: file-upload-security
language: es
source_revision: "4c215e6f"
version: "1.0.0"
title: "Seguridad de subida de archivos"
description: "Validar uploads de usuarios: magic bytes de MIME, saneo de nombres de archivo, límites de tamaño, dominio separado para servir, scanning AV, detección de polyglots"
category: prevention
severity: high
applies_to:
  - "al generar un endpoint HTTP de subida de archivos"
  - "al cablear upload por URL prefirmada a S3 / GCS / Azure Blob"
  - "al agregar procesamiento de imagen/PDF/documento de uploads de usuario"
  - "al revisar storage y serving de contenido generado por el usuario"
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

# Seguridad de subida de archivos

## Reglas (para agentes de IA)

### SIEMPRE
- Verificar los **magic bytes** de cada upload del lado servidor.
  `Content-Type` y la extensión del archivo están bajo control del
  atacante y nunca son suficientes. Usar libmagic, `file-type`
  (Node), `mimetypes-magic` (Python) o Tika.
- Mantener una **allowlist** de tipos aceptados por endpoint
  (`image/png`, `image/jpeg`, `application/pdf`, …). Denegar todo lo
  demás, incluido `text/html`, `image/svg+xml` (porta `<script>`),
  `text/xml` y `application/octet-stream`.
- Sanear nombres de archivo: quitar componentes de directorio,
  normalizar Unicode, rechazar `..`, byte NUL, caracteres de
  control, nombres reservados de Windows (`CON`, `PRN`, `AUX`,
  `NUL`, `COM1-9`, `LPT1-9`) y cualquier carácter no
  `[a-zA-Z0-9._-]`. Guardar como UUID / hash y mantener el nombre
  original en una columna de metadatos separada y escapada.
- Imponer un **límite de tamaño** en el proxy / API gateway *y* en
  la aplicación — al menos doble capa. El límite del proxy previene
  DoS de ancho de banda; el de la app previene exhaustión de memoria
  cuando el proxy está mal configurado.
- Almacenar uploads **fuera del document root** y servirlos desde un
  dominio separado (`usercontent.example.net`) sobre CDN. Setear
  `Content-Disposition: attachment` para tipos no-imagen y un header
  `Content-Security-Policy: default-src 'none'; sandbox` para
  neutralizar cualquier HTML/SVG renderizado inline.
- Correr un **antivirus** (ClamAV, VirusTotal, Sophos) sobre cada
  upload antes de hacerlo accesible a otros usuarios — fuera de
  banda para que el request en sí no quede atado a la latencia.
- Re-encodear media del lado servidor: `convert in.jpg out.jpg`
  (ImageMagick con `policy.xml` estricto), `ffmpeg -i` para video,
  `pdftocairo` para PDFs. Re-encodear elimina la mayoría de payloads
  polyglot / esteganográficos y exploits exóticos de códec.
- Para SVG específicamente: o renderizar del lado servidor a formato
  raster, o pasar por un sanitizer con allowlist estricta (DOMPurify
  en Node, `lxml.html.clean` en Python) que quite `<script>`,
  `<iframe>`, `<foreignObject>`, `xlink:href` con `javascript:`, y
  CSS con expression / url() con URIs no-data.

### NUNCA
- Confiar en el `Content-Type` del cliente. El sniffer MIME de IE /
  Chrome más viejo lee el body en busca de pistas de tipo — un
  payload HTML disfrazado de `image/png` correrá como HTML cuando se
  sirva same-origin.
- Construir el path de storage con el filename suministrado por el
  usuario. Path traversal (`../../etc/passwd`) y la clase de nombres
  reservados de Windows se reducen ambos a "dejar que el atacante
  elija dónde escribir".
- Servir uploads desde el mismo origen que la aplicación. Servir en
  `api.example.com/uploads/x.html` significa que un upload HTML
  malicioso correrá con acceso completo a las cookies de
  api.example.com y a CORS.
- Usar un stack que procese uploads con ImageMagick / libraw /
  ExifTool / ffmpeg sin policy.xml estricto / sandbox / control de
  versión. ImageTragick (CVE-2016-3714) y GitLab ExifTool
  (CVE-2021-22205) dependieron ambos de un servidor entregando
  alegremente bytes controlados por el usuario a una librería de
  media.
- Permitir upload + render in-browser de PDF sin verificar que el PDF
  pase validación estructural (p. ej. `pdfinfo`). Los PDFs maliciosos
  son un primitivo común de RCE por JavaScript-en-PDF / XFA contra
  Adobe Reader del lado del receptor, aún cuando el servidor sea
  seguro.
- Usar extracción de `.docx` / `.xlsx` / `.zip` con `unzip` o
  `python -m zipfile` sin un extractor seguro contra path traversal.
  Zip slip (CVE-2018-1002201) extrajo archivos fuera del directorio
  objetivo a través de entradas `../`.
- Usar URLs prefirmadas de upload a S3 / GCS sin una condición
  firmada estricta de `Content-Type` y un prefijo de object-key fijo.
  Sin las condiciones, el cliente puede subir cualquier cosa a
  cualquier clave.

### FALSOS POSITIVOS CONOCIDOS
- Uploads internos sólo de admin (p. ej. un dashboard de ops) pueden
  legítimamente confiar en la extensión del archivo porque el trust
  boundary es SSO + allowlist de IP. Documentar esto como decisión
  deliberada en el endpoint.
- Algunas integraciones (p. ej. exportar CSV desde herramientas de
  BI) necesitan hacer round-trip de filenames suministrados por el
  usuario; preservarlos en metadata, pero el nombre on-disk debe
  seguir siendo un UUID.
- Tarballs / DEBs / RPMs en un pipeline de build no necesitan scan
  AV — el trust boundary es la clave de firma del pipeline de build,
  no el AV.

## Contexto (para humanos)

La subida de archivos es la superficie de ataque rica y persistente.
Todo laboratorio de breach del mundo real incluye una jugada
temprana de "encontrar un formulario de upload" porque el camino de
upload a RCE suele ser corto: subir un archivo HTML con un robador
de credenciales por JavaScript, subir un shell PHP / JSP a un
doc-root mal configurado, subir un SVG con un `<script>` robador de
SAML, subir una imagen con payload en EXIF a un servicio
ImageMagick vulnerable.

Las defensas son bien conocidas y baratas — el bug es que tienen
que aplicarse en combinación. Una allowlist de magic bytes es
trivialmente eludida por un polyglot (un archivo que es
simultáneamente un PNG válido y una página HTML válida). Un dominio
de serving separado neutraliza la ejecución de HTML del polyglot.
Un antivirus atrapa malware conocido. Re-encodear elimina payloads
raros de códec. Cada defensa es una capa; al faltar una capa, la
mayoría de los uploads pasa de "datos almacenados" a "RCE
almacenado".

## Referencias

- `rules/upload_validation.json`
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
- [CWE-434](https://cwe.mitre.org/data/definitions/434.html).
- [CWE-22 (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html).
- [Snyk Zip Slip directory](https://snyk.io/research/zip-slip-vulnerability).
- [ImageTragick (CVE-2016-3714)](https://imagetragick.com/).
