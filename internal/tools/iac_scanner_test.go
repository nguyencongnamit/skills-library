package tools

import "testing"

// ruleIDSet collapses a finding slice into a set of rule IDs for
// order-independent assertions.
func ruleIDSet(fs []IaCFinding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.RuleID]++
	}
	return m
}

func TestScanIaCTerraformInsecure(t *testing.T) {
	lib := newLibrary(t)
	body := `provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  insecure   = true
}

resource "aws_security_group" "open" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{ Action = "*", Resource = "*" }]
  })
}

resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
}
`
	path := writeTempFile(t, "main.tf", body)
	res, err := lib.ScanIaC(path)
	if err != nil {
		t.Fatalf("ScanIaC: %v", err)
	}
	if res.Kind != IaCTerraform {
		t.Fatalf("Kind = %q, want terraform", res.Kind)
	}
	got := ruleIDSet(res.Findings)
	for _, want := range []string{
		"tf-no-hardcoded-creds", "tf-no-skip-tls", "tf-security-group-no-world-admin",
		"tf-iam-no-wildcard", "tf-rds-not-public", "tf-storage-encrypted",
	} {
		if got[want] == 0 {
			t.Errorf("expected rule %q to fire; got %v", want, got)
		}
	}
}

func TestScanIaCTerraformClean(t *testing.T) {
	lib := newLibrary(t)
	body := `terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted   = true
}
`
	path := writeTempFile(t, "main.tf", body)
	res, err := lib.ScanIaC(path)
	if err != nil {
		t.Fatalf("ScanIaC: %v", err)
	}
	if res.Kind != IaCTerraform {
		t.Fatalf("Kind = %q, want terraform", res.Kind)
	}
	if len(res.Findings) != 0 {
		t.Errorf("clean terraform should have 0 findings, got %d: %+v", len(res.Findings), res.Findings)
	}
}

func TestScanIaCKubernetesInsecure(t *testing.T) {
	lib := newLibrary(t)
	body := `apiVersion: v1
kind: Pod
metadata:
  name: insecure
spec:
  hostNetwork: true
  containers:
    - name: app
      image: myapp@sha256:abc
      securityContext:
        privileged: true
        runAsUser: 0
        capabilities:
          drop:
            - ALL
          add:
            - SYS_ADMIN
  volumes:
    - name: host
      hostPath:
        path: /
`
	path := writeTempFile(t, "pod.yaml", body)
	res, err := lib.ScanIaC(path)
	if err != nil {
		t.Fatalf("ScanIaC: %v", err)
	}
	if res.Kind != IaCKubernetes {
		t.Fatalf("Kind = %q, want kubernetes", res.Kind)
	}
	got := ruleIDSet(res.Findings)
	for _, want := range []string{
		"k8s-no-host-namespaces", "k8s-no-privileged", "k8s-run-as-non-root",
		"k8s-drop-all-capabilities", "k8s-no-host-paths",
	} {
		if got[want] == 0 {
			t.Errorf("expected rule %q to fire; got %v", want, got)
		}
	}
}

// TestScanIaCDropAllNotFlagged is the critical false-positive guard: the
// recommended `drop: [ALL]` must NOT trip k8s-drop-all-capabilities, and a
// benign added capability (NET_BIND_SERVICE) must not either.
func TestScanIaCDropAllNotFlagged(t *testing.T) {
	lib := newLibrary(t)
	body := `apiVersion: v1
kind: Pod
metadata:
  name: secure
spec:
  containers:
    - name: app
      image: myapp@sha256:abc
      securityContext:
        runAsNonRoot: true
        runAsUser: 10000
        privileged: false
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL
          add:
            - NET_BIND_SERVICE
`
	path := writeTempFile(t, "pod.yaml", body)
	res, err := lib.ScanIaC(path)
	if err != nil {
		t.Fatalf("ScanIaC: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("restricted pod (drop ALL, add NET_BIND_SERVICE) should have 0 findings, got %d: %+v",
			len(res.Findings), res.Findings)
	}
}

// TestScanIaCInlineCapabilities covers the flow-array form
// `add: ["SYS_ADMIN", "NET_ADMIN"]`.
func TestScanIaCInlineCapabilities(t *testing.T) {
	lib := newLibrary(t)
	body := `apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      securityContext:
        capabilities:
          drop: ["ALL"]
          add: ["SYS_ADMIN", "NET_ADMIN"]
`
	path := writeTempFile(t, "pod.yaml", body)
	res, err := lib.ScanIaC(path)
	if err != nil {
		t.Fatalf("ScanIaC: %v", err)
	}
	got := ruleIDSet(res.Findings)
	if got["k8s-drop-all-capabilities"] != 2 {
		t.Errorf("expected 2 dangerous-capability findings (SYS_ADMIN, NET_ADMIN), got %d: %+v",
			got["k8s-drop-all-capabilities"], res.Findings)
	}
}

func TestScanIaCCloudFormation(t *testing.T) {
	lib := newLibrary(t)
	bad := `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DB:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUserPassword: "SuperSecret123"
      Engine: postgres
`
	res, err := lib.ScanIaC(writeTempFile(t, "template.yaml", bad))
	if err != nil {
		t.Fatalf("ScanIaC: %v", err)
	}
	if res.Kind != IaCCloudFormation {
		t.Fatalf("Kind = %q, want cloudformation", res.Kind)
	}
	if ruleIDSet(res.Findings)["cfn-dynamic-references"] == 0 {
		t.Errorf("expected cfn-dynamic-references on a literal password; got %v", res.Findings)
	}

	good := `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DB:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUserPassword: "{{resolve:secretsmanager:db-password}}"
      Engine: postgres
`
	res2, err := lib.ScanIaC(writeTempFile(t, "template.yaml", good))
	if err != nil {
		t.Fatalf("ScanIaC: %v", err)
	}
	if len(res2.Findings) != 0 {
		t.Errorf("dynamic-reference password should be clean, got %+v", res2.Findings)
	}
}

// TestScanIaCNonIaCIsEmpty ensures scan_iac is safe to call on any file: a
// YAML that is neither k8s nor CloudFormation classifies as "" and returns
// no findings (so the directory walkers never raise false positives on
// arbitrary config files).
func TestScanIaCNonIaCIsEmpty(t *testing.T) {
	lib := newLibrary(t)
	body := "name: my-app\nversion: 1.2.3\nscripts:\n  build: make\n"
	res, err := lib.ScanIaC(writeTempFile(t, "config.yaml", body))
	if err != nil {
		t.Fatalf("ScanIaC: %v", err)
	}
	if res.Kind != "" {
		t.Errorf("plain config.yaml should not classify as IaC, got kind %q", res.Kind)
	}
	if len(res.Findings) != 0 {
		t.Errorf("non-IaC file should have 0 findings, got %+v", res.Findings)
	}
}

// TestScanIaCSARIFHasCWE verifies the SARIF emitter stamps the CWE spine
// (rule properties + run-level taxonomy) the same way the other scanners do.
func TestScanIaCSARIFHasCWE(t *testing.T) {
	lib := newLibrary(t)
	path := writeTempFile(t, "main.tf", "provider \"aws\" {\n  access_key = \"AKIAIOSFODNN7EXAMPLE\"\n}\n")
	res, err := lib.ScanIaC(path)
	if err != nil {
		t.Fatalf("ScanIaC: %v", err)
	}
	sarif := ScanIaCSARIF(res)
	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 SARIF run, got %d", len(sarif.Runs))
	}
	run := sarif.Runs[0]
	if len(run.Tool.Driver.Rules) == 0 {
		t.Fatal("expected at least one SARIF rule")
	}
	foundCWE := false
	for _, r := range run.Tool.Driver.Rules {
		if r.Properties != nil {
			if _, ok := r.Properties["cwe"]; ok {
				foundCWE = true
			}
		}
	}
	if !foundCWE {
		t.Error("expected a rule annotated with a CWE")
	}
	if len(run.Taxonomies) == 0 {
		t.Error("expected a run-level CWE taxonomy")
	}
}
