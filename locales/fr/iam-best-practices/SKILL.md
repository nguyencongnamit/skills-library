---
id: iam-best-practices
language: fr
source_revision: "6de0becf"
version: "1.0.0"
title: "Bonnes pratiques d'Identity & Access Management"
description: "Conception IAM en moindre privilège, rotation des clés, application de la MFA, prise de rôle et patterns d'accès cross-account pour AWS / GCP / Azure / Kubernetes"
category: prevention
severity: critical
applies_to:
  - "lors de la génération de policies, rôles ou documents de trust IAM"
  - "lors du câblage de service accounts CI/CD ou de workload identities"
  - "lors de la revue de création, rotation ou révocation d'access keys"
  - "lors de la conception d'accès cross-account ou cross-tenant"
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

# Bonnes pratiques d'Identity & Access Management

## Règles (pour les agents IA)

### TOUJOURS
- Accorder les permissions **minimales** requises par le job déclaré
  du workload (NIST AC-6). Démarrer avec une policy deny-by-default
  et ajouter des actions concrètes avec des ARN `Resource` explicites ;
  jamais `Action: "*"` combiné à `Resource: "*"`.
- Préférer la **workload identity** (IAM roles for service accounts
  sur EKS, GKE Workload Identity, Azure Managed Identity) aux access
  keys de longue durée. Les access keys statiques sont l'exception,
  pas le défaut.
- Exiger la **MFA** pour chaque utilisateur IAM humain, particulière-
  ment tout principal capable d'assumer un rôle privilégié. Forcer la
  MFA via une condition dans la policy IAM
  (`aws:MultiFactorAuthPresent: true`), pas seulement par un réglage
  au niveau de l'annuaire.
- Faire tourner les access keys, les service-account keys et les
  signing keys selon un calendrier documenté (≤ 90 jours). Détecter
  les credentials inactives (≥ 90 jours sans usage) et les désactiver
  automatiquement.
- Utiliser la **prise de rôle avec `sts:AssumeRole` + ExternalId**
  pour le trust entre comptes. L'ExternalId doit être unique par
  consommateur et stocké comme secret dans les deux comptes.
- Émettre des credentials **scopées à la session** avec
  `MaxSessionDuration ≤ 1h` pour les rôles humains et ≤ 12h pour les
  rôles break-glass. Les sessions de longue durée tuent la rotation.
- Séparer les identités de **deploy** et de **runtime**. Le pipeline
  CI/CD reçoit un rôle de deploy ; le service en cours d'exécution
  reçoit un rôle de runtime distinct, sans permissions mutant IAM.
- Pour Kubernetes RBAC, scoper `Role` / `RoleBinding` à un seul
  namespace ; n'utiliser `ClusterRole` que pour de vrais objets
  cluster-wide. Auditer les bindings `cluster-admin` à chaque PR.
- Logger chaque appel mutant IAM (CloudTrail / Cloud Audit Logs /
  Azure Activity Log) vers un sink tamper-evident. Alerter sur les
  changements de policy, `iam:PassRole`, `iam:CreateAccessKey` et
  `sts:AssumeRole` venant de principals inattendus.
- Pour l'accès **break-glass** (root, owner, cluster-admin), exiger
  une approbation hors-bande (p. ex. incident PagerDuty + ticket) et
  émettre une alerte immédiate à chaque usage.
- Tagger chaque principal IAM avec `owner`, `environment` et
  `purpose`. Utiliser ces tags dans les SCPs / org policies pour
  restreindre le rayon d'impact.

### JAMAIS
- Utiliser le compte **root** pour les opérations du quotidien. Les
  credentials root reçoivent un dispositif MFA matériel, sont rangées
  hors ligne, et ne servent que pour le petit ensemble de tâches
  root-only (p. ex. clôture du compte, changement de plan de
  support).
- Embarquer des access keys de longue durée dans le source, les
  images de container, les AMIs ou les variables d'environnement de
  CI quand une workload identity est disponible.
- Accorder `iam:PassRole` avec `Resource: "*"`. Toujours épingler
  les ARN de rôle que l'appelant peut passer aux services en aval.
- Accorder `iam:*` ou `sts:*` à un workload de runtime — ces
  permissions ne sont valides qu'au deploy.
- Partager un même IAM user entre plusieurs humains ou services. Un
  principal par identité, c'est l'invariant d'audit.
- Utiliser la managed policy `AdministratorAccess` (ou n'importe
  quel `*:*`) de manière routinière ; la traiter comme un
  attachement réservé aux break-glass.
- Faire confiance à un assume-role cross-account sans condition
  `ExternalId` pour des intégrations tierces (Confused Deputy : AWS
  Security Bulletin 2021).
- Mettre en dur des ARN / resource IDs AWS / GCP / Azure dans des
  documents de policy sans un scope correspondant à base de tags ou
  de chemin d'organisation (quand le nombre de ressources peut
  croître).
- Désactiver la MFA pour un principal afin de « régler » un problème
  de login — faire tourner le dispositif, ne pas supprimer
  l'exigence.
- Persister des tokens d'assertion OIDC / SAML au-delà de leur TTL
  déclaré. Rafraîchir par ré-assertion, pas en stockant le token
  d'origine.

### FAUX POSITIFS CONNUS
- `Resource: "*"` est acceptable pour les opérations de lecture
  intrinsèquement scopées au compte comme `ec2:DescribeRegions` ou
  `sts:GetCallerIdentity` — ces APIs n'acceptent pas d'ARN de
  ressource.
- Les service-linked roles (p. ex. `AWSServiceRoleForAutoScaling`)
  arrivent avec des permissions plus larges que vos rôles custom ;
  c'est par conception et géré par le provider.
- Les opérateurs de bootstrap one-shot (runners Terraform dans un
  compte vierge) ont souvent besoin de permissions élevées ;
  restreindre par tag / SCP et révoquer une fois le bootstrap fini.
- Les émulateurs de dev local (LocalStack, émulateur GCS) peuvent
  accepter n'importe quelle credential ; c'est une propriété de
  l'émulateur, pas un vrai grant.

## Contexte (pour les humains)

L'identity & access management est le fondement de chaque contrôle
de sécurité dans le cloud. Les modes de panne récurrents sont : les
policies trop permissives (`*:*`), les access keys de longue durée
committées dans git, l'absence de MFA sur des comptes privilégiés,
et les trust policies `AssumeRole` sans `ExternalId`. Ce sont les
mêmes causes racines documentées dans les fuites Capital One (2019),
Verkada (2021) et Uber (2022).

Les contrôles à fort levier sont :

1. **Workload identity plutôt qu'access keys.** Un pod sur EKS qui
   assume un rôle via IRSA n'a jamais besoin d'une credential qui
   peut fuir.
2. **MFA sur chaque humain, forcée par policy.** Un mot de passe
   fuité seul ne suffit plus à agir.
3. **Grants en moindre privilège revus au moment du PR.** Le moment
   le moins cher pour restreindre une permission, c'est quand on
   l'ajoute — pas six mois plus tard quand un auditeur la demande.
4. **Rotation des clés obligatoire.** Les credentials statiques
   vieillissent silencieusement en passif ; automatiser la rotation
   pour qu'elle ne soit pas sautée.
5. **Trust cross-account avec ExternalId.** La classe d'attaques
   Confused Deputy est intégralement mitigée par une convention
   d'ExternalId.

Ce skill applique ces contrôles quand les assistants IA génèrent
des policies IAM, des documents de trust ou des identités CI/CD.

## Références

- `rules/iam_policy_invariants.json`
- `rules/key_rotation_policy.json`
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).
- [Google Cloud IAM recommender](https://cloud.google.com/iam/docs/recommender-overview).
- [NIST SP 800-53 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf).
- [CIS Controls v8](https://www.cisecurity.org/controls/v8).
- [CNCF Kubernetes RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).
