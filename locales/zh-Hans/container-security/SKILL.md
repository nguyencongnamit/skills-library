---
id: container-security
language: zh-Hans
source_revision: "afe376a8"
version: "1.0.0"
title: "容器安全"
description: "Dockerfile、OCI 镜像、Kubernetes manifest 和 Helm chart 的加固规则"
category: hardening
severity: high
applies_to:
  - "在生成 Dockerfile 或 OCI 镜像构建时"
  - "在生成 Kubernetes / Helm / Kustomize manifest 时"
  - "在 PR 中评审容器相关变更时"
languages: ["dockerfile", "yaml", "go", "python"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2500
rules_path: "checklists/"
related_skills: ["infrastructure-security", "iac-security", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "CIS Docker Benchmark v1.6"
  - "CIS Kubernetes Benchmark v1.9"
  - "NIST SP 800-190 Application Container Security Guide"
  - "OWASP Docker Top 10"
---

# 容器安全

## 规则（面向 AI 代理）

### 必须
- 使用**多阶段构建**:把 builder/test 阶段与最终 runtime 镜像分离,
  避免把构建工具链和源码一起发出去。最后一个阶段应当是
  `FROM distroless`、`FROM scratch`、`FROM alpine:<digest>` 或其他最小化
  基础——按 SHA256 digest 固定,不要只用 tag。
- 以非 root 用户运行:`USER <uid>`(数值 UID >= 10000,K8s 的
  `runAsNonRoot` 才能强制生效)。
- 添加 `.dockerignore`,排除 `.git`、`node_modules`、`.env`、`*.pem`、
  `*.key`、`target/`、`.terraform/`、`dist/`、`coverage/`。
- 对长时间运行的服务声明显式 `HEALTHCHECK`,并在 K8s 中配置对应的
  `livenessProbe` / `readinessProbe` / `startupProbe`。
- 在每个容器上声明 CPU 和内存的 `requests` 与 `limits`。
- 删除所有 Linux capabilities,只把真正需要的加回来:
  `securityContext.capabilities.drop: [ALL]`。
- 至少应用 seccomp 配置 `RuntimeDefault`;条件允许时配合 AppArmor /
  SELinux。
- 把文件系统标为只读:`readOnlyRootFilesystem: true`;对少数必须可写
  的路径使用 `emptyDir` 卷。
- 在 CI 中扫描每个镜像(Trivy、Grype、Snyk,或 registry 自带扫描器),
  CRITICAL 或 HIGH 发现失败构建。
- 生产 manifest 中按 SHA256 digest 拉取基础镜像,不要按可变 tag。

### 禁止
- 让容器以 root 身份运行,或在非明确审计过的系统 pod(如 CNI 插件)
  之外使用 `privileged: true` / `allowPrivilegeEscalation: true`。
- 把宿主机的 docker socket (`/var/run/docker.sock`) 挂进应用容器。
  这等同于在宿主机上获得 root。
- 通过 `ENV`、`ARG`、`COPY` 或 `echo` 把 secret 写进镜像层。即便用了
  `--squash`,BuildKit 缓存与 registry 层仍然会泄露。
- 把 `latest`、`stable`、`slim` 或未带版本的 tag 当作最终镜像基础——
  构建会失去可复现性,并悄悄吞下 CVE。
- 用 `ADD <url>` 在构建过程中拉取远程资源(改用 `curl --fail` +
  校验 checksum + `RUN`,或者把工件 vendor 进来)。
- 当 workload 确实需要访问 K8s API 时关闭
  `automountServiceAccountToken`;但是当不需要时,**就要**关掉
  (`automountServiceAccountToken: false`)。
- 对应用 pod 使用 `hostNetwork: true`、`hostPID: true` 或
  `hostIPC: true`。
- 把 pod 放进 `kube-system` 命名空间,或任何没有 `NetworkPolicy` 与
  PodSecurity admission 策略的命名空间。

### 已知误报
- 真正需要 cluster-admin 权限的 operator(kubelet、CSI 驱动、CNI
  插件)需要较高权限;它们应属于 `kube-system` 或专门的带审计的命名
  空间,而不是应用命名空间。
- 裸金属 Kubernetes 节点有时会出于驱动兼容性合理地关闭 seccomp;
  记录这一豁免。
- 一次性调试 pod(kubectl debug、临时容器)有意绕开许多控制项;
  它们不应作为 YAML 持久化进仓库。

## 背景(面向人类)

容器的泄露主要有两条路径:镜像层泄露(`ENV` 中的 secret、留在最终
镜像里的构建工件、基础镜像里的 CVE)与运行时逃逸(特权模式、
docker.sock、宿主机命名空间)。NIST SP 800-190 把它们分类为
**镜像风险**、**registry 风险**、**编排器风险**和**运行时风险**。

AI 助手几乎总会生成"能跑、能发"的 Dockerfile——速度很快——但默认是
单阶段的 `FROM node` / `FROM python` 加上 `USER root`。本 skill 是对
这种倾向的反制;与 `infrastructure-security` 配合可以覆盖 pod 之外
的 K8s 控制项(RBAC、admission、supply chain)。

## 参考

- `checklists/dockerfile_hardening.yaml`
- `checklists/k8s_pod_security.yaml`
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes).
- [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final).
