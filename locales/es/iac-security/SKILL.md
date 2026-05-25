---
id: iac-security
language: es
source_revision: "afe376a8"
version: "1.0.0"
title: "Seguridad de Infrastructure-as-Code"
description: "Reglas de hardening para Terraform, CloudFormation y Pulumi: state, providers, drift, secretos"
category: hardening
severity: high
applies_to:
  - "al generar Terraform / Pulumi / CloudFormation"
  - "al revisar cambios de IaC en un PR"
  - "al cablear una nueva cuenta o workspace en la nube"
languages: ["hcl", "yaml", "json", "typescript", "python", "go"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2500
rules_path: "checklists/"
related_skills: ["infrastructure-security", "container-security", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "CIS Benchmarks (AWS, Azure, GCP)"
  - "HashiCorp Terraform Best Practices"
  - "NIST SP 800-53 Rev. 5 (CM-6, CM-8, SC-28)"
  - "OWASP IaC Security Top 10"
---

# Seguridad de Infrastructure-as-Code

## Reglas (para agentes de IA)

### SIEMPRE
- Fijar cada provider/módulo a una versión exacta o a una restricción
  pesimista (`~> 5.42`); nunca `>= 0` ni un `latest` sin pin.
- Configurar un **backend remoto** con cifrado en reposo, locking de
  state del lado del servidor, y versionado (Terraform: `s3` +
  DynamoDB lock table con `kms_key_id`; Pulumi: el backend gestionado
  o `s3://?kmskey=`; CloudFormation: gestionado por AWS).
- Cifrar por defecto cada recurso persistente con una clave KMS
  gestionada por el cliente: buckets S3, volúmenes EBS, RDS, EFS,
  DynamoDB, SQS, SNS, CloudWatch log groups.
- Etiquetar cada recurso con `owner`, `environment`, `cost-center` y
  `data-classification` vía un bloque de default tags.
- Correr `terraform plan` (o `pulumi preview`,
  `aws cloudformation deploy --no-execute-changeset`) en CI y
  requerir aprobación humana antes del `apply` en stacks de
  producción.
- Agregar un job de detección de drift que corra diariamente y abra
  un issue cuando el estado real en la nube diverja del código
  (Terraform Cloud drift detection, `pulumi refresh`,
  `cfn-drift-detect`).
- Usar Conditions de IAM para acotar cada role: `aws:SourceArn`,
  `aws:SourceAccount`, `aws:PrincipalOrgID`, y policies de acceso
  TLS-only sobre storage.

### NUNCA
- Hardcodear credenciales del provider en el código o en `.tfvars`
  (`access_key`, `secret_key`, `client_secret`,
  `service_account_key`). Usar federación OIDC desde CI, el servicio
  de metadatos de instancia del provider, o un secret manager.
- Commitear `terraform.tfstate`, `terraform.tfstate.backup`,
  `.pulumi/`, o cualquier `*.tfvars` que contenga secretos reales.
  Contienen secretos en texto plano aunque el código referencie
  variables.
- Usar `local_exec` / `null_resource` para traer secretos al momento
  del apply y meterlos en el state. El state es texto plano
  consultable por cualquiera con acceso de lectura al backend.
- Abrir security groups / reglas de firewall a `0.0.0.0/0` para los
  puertos 22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, 11211 —
  ni siquiera para "es sólo dev". Usar bastión o VPN.
- Otorgar policies IAM `*:*` (acción wildcard sobre recurso
  wildcard). Usar `iam:PassRole` con ARNs de recurso explícitos.
- Deshabilitar la verificación TLS del provider (`skip_tls_verify`,
  `insecure = true`).
- Usar `count = 0` para "borrar lógicamente" recursos que en realidad
  querés que desaparezcan — destruirlos.

### FALSOS POSITIVOS CONOCIDOS
- Los bastion hosts deliberadamente expuestos en el puerto 22 a
  internet con configuraciones endurecidas no son el mismo riesgo
  que abrir RDS al mundo. Documentar la excepción inline.
- Distribuciones CloudFront públicas, listeners de ALB en 80/443,
  API Gateways y URLs de funciones Lambda que *sí* están pensados
  para estar de cara a internet.
- Los recursos de bootstrap (el bucket S3 y la DynamoDB lock table
  que el backend mismo usa) deben existir antes de que pueda haber
  state remoto; este círculo huevo-y-gallina se suele bootstrappear
  con un backend `local` de una sola vez que después se migra.

## Contexto (para humanos)

Los errores de IaC escalan: un solo módulo malo se aplica con
`terraform apply` a cientos de cuentas. Las clases de problema que
cubrimos acá — fugas de secretos vía state, exposición de red sin
límite, IAM con wildcards, drift — son exactamente lo que CIS y las
revisiones well-architected de los propios proveedores cloud marcan
más. Los asistentes IA son particularmente propensos a generar
Terraform "me funciona en mi máquina" que no pinea nada y usa state
local; este skill es el contrapeso.

## Referencias

- `checklists/terraform_hardening.yaml`
- `checklists/cloudformation_hardening.yaml`
- [CIS Benchmark for Amazon Web Services Foundations](https://www.cisecurity.org/benchmark/amazon_web_services).
- [Terraform Recommended Practices](https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices).
- [NIST SP 800-53 Rev. 5 control catalog](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final).
