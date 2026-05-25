---
id: file-upload-security
language: pt-BR
source_revision: "4c215e6f"
version: "1.0.0"
title: "Segurança em upload de arquivos"
description: "Validar uploads de usuário: magic bytes de MIME, saneamento de nome de arquivo, limites de tamanho, domínio separado para servir, scan AV, detecção de polyglots"
category: prevention
severity: high
applies_to:
  - "ao gerar um endpoint HTTP de upload de arquivo"
  - "ao configurar upload por URL pré-assinada para S3 / GCS / Azure Blob"
  - "ao adicionar processamento de imagem/PDF/documento de uploads do usuário"
  - "ao revisar storage e serving de conteúdo gerado pelo usuário"
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

# Segurança em upload de arquivos

## Regras (para agentes de IA)

### SEMPRE
- Verifique os **magic bytes** de cada upload no lado servidor.
  `Content-Type` e a extensão do arquivo são controlados pelo
  atacante e nunca são suficientes. Use libmagic, `file-type`
  (Node), `mimetypes-magic` (Python) ou Tika.
- Mantenha uma **allowlist** de tipos aceitos por endpoint
  (`image/png`, `image/jpeg`, `application/pdf`, …). Negue todo o
  resto, incluindo `text/html`, `image/svg+xml` (carrega
  `<script>`), `text/xml` e `application/octet-stream`.
- Sanitize nomes de arquivo: retire componentes de diretório,
  normalize Unicode, rejeite `..`, byte NUL, caracteres de
  controle, nomes reservados do Windows (`CON`, `PRN`, `AUX`,
  `NUL`, `COM1-9`, `LPT1-9`) e qualquer caractere fora de
  `[a-zA-Z0-9._-]`. Armazene como UUID / hash e mantenha o nome
  original em uma coluna de metadados separada e escapada.
- Imponha um **limite de tamanho** no proxy / API gateway *e* na
  aplicação — pelo menos camada dupla. O limite do proxy previne
  DoS de banda; o limite da app previne exaustão de memória quando
  um proxy está mal configurado.
- Armazene uploads **fora do document root** e sirva-os de um
  domínio separado (`usercontent.example.net`) via CDN. Defina
  `Content-Disposition: attachment` para tipos não-imagem e um
  header `Content-Security-Policy: default-src 'none'; sandbox`
  para neutralizar qualquer HTML/SVG renderizado inline.
- Rode um **scanner de vírus** (ClamAV, VirusTotal, Sophos) em cada
  upload antes de torná-lo acessível a outros usuários — fora de
  banda para que o request em si não fique preso à latência.
- Re-codifique mídia no lado servidor: `convert in.jpg out.jpg`
  (ImageMagick com `policy.xml` estrito), `ffmpeg -i` para vídeo,
  `pdftocairo` para PDFs. A re-codificação remove a maior parte dos
  payloads polyglot / esteganográficos e exploits exóticos de codec.
- Para SVG especificamente: ou renderize no lado servidor para um
  formato raster, ou passe por um sanitizer com allowlist estrita
  (DOMPurify em Node, `lxml.html.clean` em Python) que remova
  `<script>`, `<iframe>`, `<foreignObject>`, `xlink:href` com
  `javascript:` e CSS com expression / url() com URIs não-data.

### NUNCA
- Confie no `Content-Type` vindo do cliente. O sniffer de MIME do
  IE / Chrome mais antigos lê o body em busca de pistas de tipo —
  um payload HTML disfarçado de `image/png` rodará como HTML quando
  servido same-origin.
- Construa o path de storage com o filename fornecido pelo usuário.
  Path traversal (`../../etc/passwd`) e a classe de nomes reservados
  do Windows reduzem-se ambos a "deixar o atacante escolher onde
  escrever".
- Sirva uploads do mesmo origin da aplicação. Servir em
  `api.example.com/uploads/x.html` significa que um upload HTML
  malicioso roda com acesso completo aos cookies de
  api.example.com e ao CORS.
- Use um stack que processe uploads com ImageMagick / libraw /
  ExifTool / ffmpeg sem policy.xml estrito / sandbox / controle de
  versão. ImageTragick (CVE-2016-3714) e GitLab ExifTool
  (CVE-2021-22205) ambos dependeram de um servidor entregando
  alegremente bytes controlados pelo usuário a uma biblioteca de
  mídia.
- Permita upload + render in-browser de PDF sem verificar se o PDF
  passa em validação estrutural (ex.: `pdfinfo`). PDFs maliciosos
  são um primitivo comum de RCE por JavaScript-no-PDF / XFA contra
  o Adobe Reader no lado do destinatário, mesmo quando o servidor é
  seguro.
- Use extração de `.docx` / `.xlsx` / `.zip` com `unzip` ou
  `python -m zipfile` sem extractor seguro contra path traversal.
  Zip slip (CVE-2018-1002201) extraiu arquivos fora do diretório
  alvo via entradas `../`.
- Use URLs pré-assinadas de upload do S3 / GCS sem uma condition
  estrita e assinada de `Content-Type` e um prefixo fixo de
  object-key. Sem as conditions, o cliente pode subir qualquer coisa
  para qualquer chave.

### FALSOS POSITIVOS CONHECIDOS
- Uploads internos apenas de admin (ex.: um dashboard de ops) podem
  legitimamente confiar na extensão do arquivo porque o trust
  boundary é SSO + allowlist de IP. Documente isso como decisão
  deliberada no endpoint.
- Algumas integrações (ex.: exportar CSV de ferramentas de BI)
  precisam fazer round-trip de filenames fornecidos pelo usuário;
  preserve-os em metadata, mas o nome em disco precisa continuar
  sendo um UUID.
- Tarballs / DEBs / RPMs em pipeline de build não precisam de scan
  AV — o trust boundary é a chave de assinatura do pipeline de
  build, não o AV.

## Contexto (para humanos)

Upload de arquivo é a superfície de ataque rica e persistente. Todo
lab de breach do mundo real inclui um lance de early-game de
"encontrar um formulário de upload" porque o caminho do upload ao
RCE costuma ser curto: subir um arquivo HTML com um ladrão de
credenciais em JavaScript, subir um shell PHP / JSP em um doc-root
mal configurado, subir um SVG com um `<script>` ladrão de SAML,
subir uma imagem com payload no EXIF em um serviço ImageMagick
vulnerável.

As defesas são bem compreendidas e baratas — o bug é que precisam
ser aplicadas em combinação. Uma allowlist de magic bytes é
trivialmente contornada por um polyglot (um arquivo que é
simultaneamente um PNG válido e uma página HTML válida). Um domínio
de serving separado neutraliza a execução de HTML do polyglot. Um
scanner de vírus pega malware conhecido. Re-codificar remove
payloads estranhos de codec. Cada defesa é uma camada; faltando
uma, a maior parte dos uploads vira de "dados armazenados" em "RCE
armazenado".

## Referências

- `rules/upload_validation.json`
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
- [CWE-434](https://cwe.mitre.org/data/definitions/434.html).
- [CWE-22 (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html).
- [Snyk Zip Slip directory](https://snyk.io/research/zip-slip-vulnerability).
- [ImageTragick (CVE-2016-3714)](https://imagetragick.com/).
