---
id: infrastructure-security
language: de
source_revision: "fbb3a823"
version: "1.0.0"
title: "Infrastruktur-Sicherheit"
description: "Härtungsregeln für Kubernetes, Docker und Terraform-Infrastructure-as-Code anwenden"
category: hardening
severity: high
applies_to:
  - "beim Erzeugen von Dockerfile-Inhalten"
  - "beim Erzeugen von Kubernetes-Manifests oder Helm-Charts"
  - "beim Erzeugen von Terraform oder CloudFormation"
  - "beim Review von IaC-PRs"
languages: ["yaml", "hcl", "dockerfile"]
token_budget:
  minimal: 650
  compact: 950
  full: 2500
rules_path: "checklists/"
related_skills: ["api-security", "compliance-awareness"]
last_updated: "2026-05-12"
sources:
  - "CIS Kubernetes Benchmark"
  - "CIS Docker Benchmark"
  - "NSA/CISA Kubernetes Hardening Guidance"
  - "HashiCorp Terraform Security Best Practices"
---

# Infrastruktur-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- Base-Images per Digest pinnen (`FROM image@sha256:...`), wenn
  Container für die Produktion gebaut werden. Tags sind veränderlich;
  Digests nicht.
- Container als Nicht-Root-`USER` ungleich `0` ausführen.
  `securityContext: runAsNonRoot: true` zu K8s-Pod-Specs hinzufügen.
- Explizite Kubernetes-Ressourcen-Requests UND -Limits setzen
  (`requests.cpu`, `requests.memory`, `limits.cpu`, `limits.memory`).
- Alle Linux-Capabilities droppen und nur das wieder hinzufügen, was
  benötigt wird (`securityContext.capabilities.drop: ["ALL"]`).
- Dateisysteme read-only markieren
  (`securityContext.readOnlyRootFilesystem: true`), wenn der Workload
  legitim keinen Write-Zugriff braucht.
- Verschlüsselung im Ruhezustand aktivieren
  (`enable_kms_encryption`, `kms_key_id`,
  `server_side_encryption_configuration`) für S3-Buckets, EBS-Volumes,
  RDS, DynamoDB.
- `block_public_access` auf jedem S3-Bucket setzen, ausser der Workload
  bedient wirklich öffentlichen Inhalt.
- Das Prinzip des geringsten Privilegs auf IAM-Policies anwenden:
  explizite Actions und Ressourcen benennen; `*:*` und
  `Resource: "*"` ausserhalb absichtlicher Admin-Policies vermeiden.

### NIE
- `latest` als Image-Tag in Produktions-Manifests verwenden.
- Container mit `--privileged`-Flag oder
  `securityContext.privileged: true` ausführen.
- Den Host-`/var/run/docker.sock` in einen Container mounten.
- Kubernetes-Services per `type: LoadBalancer` ohne vorgeschalteten
  Ingress-Controller, WAF oder Authentifizierungs-Layer ins offene
  Internet exponieren.
- AWS-Keys / GCP-Service-Account-Keys / Azure-Client-Secrets in IaC
  hardcoden. IRSA, GKE Workload Identity, Azure Managed Identities oder
  das plattform-eigene Äquivalent verwenden.
- S3-Buckets mit `acl = "public-read"` für Buckets erstellen, die
  irgendetwas anderes als absichtlich öffentliche Assets enthalten.
- `0.0.0.0/0`-Ingress auf Datenbank-, SSH-, RDP- oder Admin-Ports
  zulassen.
- `node_to_node_encryption` auf Elasticsearch / OpenSearch
  deaktivieren.

### BEKANNTE FALSCH-POSITIVE
- Image-Digest-Pinning ist in Dev-/Preview-Umgebungen nicht immer
  praktikabel — Tag-Pinning (z. B. `node:20.11.1-alpine`) ist dort
  akzeptabel.
- `Resource: "*"` ist akzeptabel in Policies, die dokumentiert
  ausschliesslich Admin-only sind, mit expliziten
  `Condition`-Einschränkungen.
- `runAsNonRoot: false` ist akzeptabel, wenn der Workload legitim
  Root benötigt (z. B. Binden an Port 80, bestimmte Netzwerk-Tools).
  Begründung dokumentieren.

## Kontext (für Menschen)

Fehlkonfigurierte Infrastruktur ist die dominierende Ursache von
Cloud-Breaches. Die obigen Muster kodifizieren die am häufigsten
verletzten CIS-Benchmark-Items als Regeln, die die KI während der
Generierung anwendet, nicht erst nach dem Deploy.

## Referenzen

- `checklists/k8s_hardening.yaml`
- `checklists/docker_security.yaml`
- `checklists/terraform_security.yaml`
- [NSA/CISA Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF).
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
