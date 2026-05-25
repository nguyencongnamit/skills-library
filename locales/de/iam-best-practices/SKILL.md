---
id: iam-best-practices
language: de
source_revision: "6de0becf"
version: "1.0.0"
title: "Best Practices für Identity & Access Management"
description: "Least-Privilege-IAM-Design, Key-Rotation, MFA-Enforcement, Role-Assumption und Cross-Account-Access-Muster für AWS / GCP / Azure / Kubernetes"
category: prevention
severity: critical
applies_to:
  - "beim Erzeugen von IAM-Policies, -Rollen oder Trust-Dokumenten"
  - "beim Verdrahten von CI/CD-Service-Accounts oder Workload Identities"
  - "beim Review der Erstellung, Rotation oder Revokation von Access Keys"
  - "beim Design von Cross-Account- oder Cross-Tenant-Zugriff"
languages: ["hcl", "yaml", "json", "python", "go", "typescript"]
token_budget:
  minimal: 1100
  compact: 1500
  full: 2400
rules_path: "rules/"
related_skills: ["auth-security", "iac-security", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "NIST SP 800-53 Rev. 5 (AC-2, AC-3, AC-6, AC-17, IA-2, IA-5)"
  - "NIST SP 800-63B (Authenticator Assurance)"
  - "CIS Controls v8 (Controls 5 and 6)"
  - "AWS IAM Best Practices"
  - "Google Cloud IAM Recommender"
  - "Microsoft Azure RBAC Best Practices"
  - "CNCF Kubernetes RBAC Good Practices"
  - "OWASP Cloud Security Top 10"
---

# Best Practices für Identity & Access Management

## Regeln (für KI-Agenten)

### IMMER
- Die **minimalen** Berechtigungen erteilen, die der ausdrückliche Job
  des Workloads erfordert (NIST AC-6). Mit einer Deny-by-Default-Policy
  starten und konkrete Actions mit expliziten `Resource`-ARNs hinzu-
  fügen; nie `Action: "*"` kombiniert mit `Resource: "*"`.
- **Workload Identity** bevorzugen (IAM Roles für Service Accounts auf
  EKS, GKE Workload Identity, Azure Managed Identity) statt langlebiger
  Access Keys. Statische Access Keys sind die Ausnahme, nicht der
  Default.
- **MFA** für jeden menschlichen IAM-User verlangen, besonders für
  jeden Principal, der eine privilegierte Rolle assumieren kann. MFA
  über eine Bedingung in der IAM-Policy
  (`aws:MultiFactorAuthPresent: true`) erzwingen, nicht nur über eine
  Verzeichnis-Ebene-Einstellung.
- Access Keys, Service-Account-Keys und Signing Keys nach einem
  dokumentierten Zeitplan rotieren (≤ 90 Tage). Inaktive Credentials
  (≥ 90 Tage ungenutzt) erkennen und automatisch deaktivieren.
- **Role-Assumption mit `sts:AssumeRole` + ExternalId** für
  Cross-Account-Trust verwenden. Die ExternalId muss pro Consumer
  eindeutig sein und in beiden Accounts als Secret gespeichert sein.
- **Session-skopierte** Credentials mit `MaxSessionDuration ≤ 1h` für
  menschliche Rollen und ≤ 12h für Break-Glass-Rollen ausstellen.
  Lange Sessions hebeln Rotation aus.
- Identitäten für **Deploy** und **Runtime** trennen. Die CI/CD-
  Pipeline bekommt eine Deploy-Rolle; der laufende Service bekommt
  eine separate Runtime-Rolle ohne IAM-mutierende Permissions.
- Für Kubernetes-RBAC `Role` / `RoleBinding` auf einen einzelnen
  Namespace beschränken; `ClusterRole` nur für tatsächlich cluster-
  weite Objekte einsetzen. `cluster-admin`-Bindings bei jedem PR
  auditieren.
- Jeden IAM-mutierenden Call (CloudTrail / Cloud Audit Logs / Azure
  Activity Log) in einen tamper-evidenten Sink loggen. Auf Policy-
  Änderungen, `iam:PassRole`, `iam:CreateAccessKey` und
  `sts:AssumeRole` von unerwarteten Principals alarmieren.
- Für **Break-Glass**-Zugriff (root, owner, cluster-admin) eine
  Out-of-Band-Genehmigung verlangen (z. B. PagerDuty-Incident +
  Ticket) und bei jeder Nutzung sofort alarmieren.
- Jeden IAM-Principal mit `owner`, `environment` und `purpose`
  taggen. Diese Tags in SCPs / Org Policies nutzen, um den
  Blast-Radius einzugrenzen.

### NIE
- Den **Root-Account** für den Tagesbetrieb verwenden. Root-Credentials
  bekommen ein Hardware-MFA-Gerät, werden offline aufbewahrt und nur
  für die kleine Menge an Root-only-Aufgaben verwendet (z. B. Account
  schliessen, Support-Plan ändern).
- Langlebige Access Keys in Source, Container-Images, AMIs oder
  CI-Environment-Variablen einbetten, wenn eine Workload Identity
  verfügbar ist.
- `iam:PassRole` mit `Resource: "*"` vergeben. Immer die Rollen-ARNs
  pinnen, die der Caller an Downstream-Services weiterreichen darf.
- `iam:*` oder `sts:*` an einen Runtime-Workload vergeben — das sind
  ausschliesslich Deploy-Time-Permissions.
- Einen einzigen IAM-User über mehrere Menschen oder Services hinweg
  teilen. Ein Principal pro Identität ist das Audit-Invariant.
- Die Managed Policy `AdministratorAccess` (oder irgendein `*:*`)
  routinemässig nutzen; sie wie ein reines Break-Glass-Attachment
  behandeln.
- Irgendeinem Cross-Account-AssumeRole ohne `ExternalId`-Bedingung
  bei Drittpartei-Integrationen trauen (Confused Deputy: AWS
  Security Bulletin 2021).
- AWS-/GCP-/Azure-ARNs/-Resource-IDs in Policy-Dokumenten hardcoden,
  ohne entsprechenden Tag-basierten oder Organisations-Pfad-Scope
  (wenn die Anzahl der Ressourcen wachsen kann).
- MFA für einen Principal deaktivieren, um ein Login-Problem zu
  "fixen" — das Gerät rotieren, nicht die Anforderung entfernen.
- OIDC-/SAML-Assertion-Tokens über ihre angegebene TTL hinaus
  persistieren. Per Neu-Assertion erneuern, nicht den ursprünglichen
  Token speichern.

### BEKANNTE FALSCH-POSITIVE
- `Resource: "*"` ist akzeptabel für inhärent account-skopierte
  Read-Operationen wie `ec2:DescribeRegions` oder
  `sts:GetCallerIdentity` — diese APIs akzeptieren keinen
  Resource-ARN.
- Service-Linked Roles (z. B. `AWSServiceRoleForAutoScaling`) kommen
  mit breiteren Permissions als deine Custom-Roles; das ist Absicht
  und wird vom Provider verwaltet.
- Einmalige Bootstrap-Operatoren (Terraform-Runner in einem frischen
  Account) brauchen oft erhöhte Permissions; über Tag / SCP
  einschränken und nach Abschluss des Bootstraps widerrufen.
- Lokale Entwicklungsemulatoren (LocalStack, GCS-Emulator) akzeptieren
  ggf. beliebige Credentials; das ist eine Eigenschaft des Emulators,
  kein echter Grant.

## Kontext (für Menschen)

Identity & Access Management ist die Grundlage jeder Cloud-Security-
Kontrolle. Die wiederkehrenden Fehlermodi sind: zu permissive
Policies (`*:*`), langlebige Access Keys in Git eingecheckt, fehlende
MFA auf privilegierten Accounts und `AssumeRole`-Trust-Policies ohne
`ExternalId`. Das sind die gleichen Root-Causes, die in den
Capital-One- (2019), Verkada- (2021) und Uber- (2022) Breaches
dokumentiert sind.

Die Kontrollen mit dem grössten Hebel sind:

1. **Workload Identity statt Access Keys.** Ein Pod in EKS, der
   per IRSA eine Rolle assumiert, braucht nie ein Credential, das
   leaken kann.
2. **MFA für jeden Menschen, per Policy erzwungen.** Ein geleaktes
   Passwort allein reicht nicht mehr.
3. **Least-Privilege-Grants beim PR reviewen.** Der billigste
   Moment, eine Permission einzuschränken, ist beim Hinzufügen —
   nicht sechs Monate später, wenn ein Auditor fragt.
4. **Verpflichtende Key-Rotation.** Statische Credentials altern
   still zur Haftung; Rotation automatisieren, damit sie nicht
   übersprungen wird.
5. **Cross-Account-Trust mit ExternalId.** Die Confused-Deputy-
   Angriffsklasse wird durch eine ExternalId-Konvention vollständig
   mitigiert.

Dieser Skill erzwingt diese Kontrollen, wenn KI-Assistenten IAM-
Policies, Trust-Dokumente oder CI/CD-Identitäten generieren.

## Referenzen

- `rules/iam_policy_invariants.json`
- `rules/key_rotation_policy.json`
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).
- [Google Cloud IAM recommender](https://cloud.google.com/iam/docs/recommender-overview).
- [NIST SP 800-53 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf).
- [CIS Controls v8](https://www.cisecurity.org/controls/v8).
- [CNCF Kubernetes RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).
