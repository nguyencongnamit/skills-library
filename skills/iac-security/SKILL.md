---
id: iac-security
version: "1.0.0"
title: "Infrastructure-as-Code Security"
description: "Hardening rules for Terraform, CloudFormation, and Pulumi: state, providers, drift, secrets"
category: hardening
severity: high
applies_to:
  - "when generating Terraform / Pulumi / CloudFormation"
  - "when reviewing IaC changes in PR"
  - "when wiring up a new cloud account or workspace"
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

# Infrastructure-as-Code Security

## Rules (for AI agents)

### ALWAYS
- Pin every provider/module to an exact version or a pessimistic constraint
  (`~> 5.42`); never `>= 0` or unpinned `latest`.
- Configure a **remote backend** with encryption at rest, server-side state locking,
  and versioning (Terraform: `s3` + DynamoDB lock table with `kms_key_id`; Pulumi:
  the managed backend or `s3://?kmskey=`; CloudFormation: managed by AWS).
- Encrypt every persistent resource by default with a customer-managed KMS key:
  S3 buckets, EBS volumes, RDS, EFS, DynamoDB, SQS, SNS, CloudWatch log groups.
- Tag every resource with `owner`, `environment`, `cost-center`, and `data-classification`
  via a default tags block.
- Run `terraform plan` (or `pulumi preview`, `aws cloudformation deploy --no-execute-changeset`)
  in CI and require a human approval before `apply` on production stacks.
- Add a drift-detection job that runs daily and opens an issue when actual cloud
  state diverges from code (Terraform Cloud drift detection, `pulumi refresh`,
  `cfn-drift-detect`).
- Use IAM Conditions to scope every role: `aws:SourceArn`, `aws:SourceAccount`,
  `aws:PrincipalOrgID`, and TLS-only access policies on storage.

### NEVER
- Hardcode provider credentials in the code or `.tfvars` (`access_key`, `secret_key`,
  `client_secret`, `service_account_key`). Use OIDC federation from CI, the
  provider's instance metadata service, or a secret manager.
- Commit `terraform.tfstate`, `terraform.tfstate.backup`, `.pulumi/`, or any
  `*.tfvars` containing real secrets. They contain plaintext secrets even if the
  code references variables.
- Use `local_exec` / `null_resource` to fetch secrets at apply time and stash them
  in state. State is queryable plaintext by anyone with backend read access.
- Open security groups / firewall rules to `0.0.0.0/0` for ports 22, 3389, 3306,
  5432, 1433, 6379, 27017, 9200, 11211 — even for "just dev". Use bastion or VPN.
- Grant `*:*` (wildcard action on wildcard resource) IAM policies. Use `iam:PassRole`
  with explicit resource ARNs.
- Disable provider TLS verification (`skip_tls_verify`, `insecure = true`).
- Use `count = 0` to "soft-delete" resources you actually want gone — destroy them.

### KNOWN FALSE POSITIVES
- Bastion hosts intentionally exposed on port 22 to the internet with hardened
  configurations are not the same risk as opening RDS to the world. Document the
  exception inline.
- Public CloudFront distributions, ALB listeners on 80/443, API Gateways, and
  Lambda function URLs that *are* meant to be internet-facing.
- Bootstrap resources (the S3 bucket and DynamoDB lock table the backend itself
  uses) must exist before remote state can; this chicken-and-egg is usually
  bootstrapped by a one-time `local` backend that's then migrated.

## Context (for humans)

IaC mistakes scale: a single bad module gets `terraform apply`'d into hundreds of
accounts. The classes of issue we cover here — state-secret leaks, unbounded
network exposure, wildcard IAM, drift — are exactly what CIS and the cloud
providers' own well-architected reviews flag the most. AI assistants are
particularly prone to generating "works on my machine" Terraform that pins nothing
and uses local state; this skill is the counterbalance.

## References

- `checklists/terraform_hardening.yaml`
- `checklists/cloudformation_hardening.yaml`
- [CIS Benchmark for Amazon Web Services Foundations](https://www.cisecurity.org/benchmark/amazon_web_services).
- [Terraform Recommended Practices](https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices).
- [NIST SP 800-53 Rev. 5 control catalog](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final).
