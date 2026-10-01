# Kyverno Security Lab

A hands-on, practical lab for implementing Kubernetes cluster security and governance using Policy-as-Code with **Kyverno**. This project demonstrates policy enforcement using the standard, Kubernetes-native Kyverno `ClusterPolicy` (`kyverno.io/v1`).

---

## Table of Contents

- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Quick Start (Automated Lab)](#quick-start-automated-lab)
- [Step-by-Step Lab Walkthrough](#step-by-step-lab-walkthrough)
  - [1. Provision Local Cluster with Kind](#1-provision-local-cluster-with-kind)
  - [2. Install Kyverno via Helm](#2-install-kyverno-via-helm)
  - [3. Verify Kyverno Deployment](#3-verify-kyverno-deployment)
  - [4. Deploy the Security Policies](#4-deploy-the-security-policies)
  - [5. Test Policy Enforcement](#5-test-policy-enforcement)
    - [Negative Test 1: Reject Pod Without Limits](#negative-test-1-reject-pod-without-limits)
    - [Negative Test 2: Reject Privileged Container](#negative-test-2-reject-privileged-container)
    - [Positive Test: Accept Compliant Pod](#positive-test-accept-compliant-pod)
- [Policy Deep Dive: ClusterPolicy](#policy-deep-dive-clusterpolicy)
  - [Policy 1: Require Resource Limits (require-limits.yaml)](#policy-1-require-resource-limits-require-limitsyaml)
  - [Policy 2: Restrict Privileged Containers (restrict-privilege.yaml)](#policy-2-restrict-privileged-containers-restrict-privilegeyaml)
- [Testing with Kyverno CLI (Shift-Left / CI/CD)](#testing-with-kyverno-cli-shift-left--cicd)
- [Troubleshooting & Verification](#troubleshooting--verification)
- [Cleanup](#cleanup)
- [Best Practices & Next Steps](#best-practices--next-steps)

---

## Project Overview

In multi-tenant or production Kubernetes environments, uncontrolled container workloads can compromise cluster availability and security:
- **Resource Exhaustion:** Workloads missing CPU/memory limits cause noisy neighbors, CPU throttling, or Out-Of-Memory (OOM-killer) node instability.
- **Privilege Escalation & Breakout:** Containers running in privileged mode (`securityContext.privileged: true`) bypass Linux cgroups, namespaces, and AppArmor/seccomp boundaries, effectively gaining root control over the host node.

This lab demonstrates how to enforce mandatory resource governance and block dangerous privileged containers at admission time using Kyverno before any pod is scheduled onto a node.

### Why Kyverno?
- **Kubernetes-Native:** Written in declarative YAML — no custom domain-specific languages (DSLs) like Rego or Go programming required.
- **Pattern Matching:** Simple, intuitive declarative patterns to validate Kubernetes object structures.
- **Flexible Actions:** Supports both auditing (`Audit`) and active admission enforcement (`Enforce`).
- **Comprehensive Lifecycle:** Validates, mutates, generates, and cleans up Kubernetes resources.

---

## Key Features

- **Policy-as-Code:** Declarative policy definitions managed under version control.
- **Standard CRD:** Uses the production-standard `kyverno.io/v1` `ClusterPolicy` resource.
- **Pod Security Standards (Baseline & Restricted):** Blocks privileged container workloads and host root access.
- **Comprehensive Container Coverage:** Evaluates `spec.containers`, `spec.initContainers`, and `spec.ephemeralContainers`.
- **Shift-Left Ready:** Policies and manifests can be validated in CI/CD pipelines before deployment to clusters.
- **Automated Lab Runner:** Cross-platform scripts (`run-lab.sh` and `run-lab.ps1`) for one-command execution and testing.

---

## Repository Structure

```plaintext
kyverno-security-lab/
├── kind-config.yaml          # Kind multi-node cluster configuration (1 control plane, 1 worker)
├── require-limits.yaml       # Kyverno ClusterPolicy enforcing CPU & memory limits
├── restrict-privilege.yaml   # Kyverno ClusterPolicy restricting privileged mode containers
├── bad-pod.yaml              # Negative test case (violates policy, missing limits)
├── bad-pod-priv.yaml         # Negative test case (violates policy, requests privileged mode)
├── good-pod.yaml             # Positive test case (conforms to policy, limits defined, non-privileged)
├── run-lab.sh                # Automated end-to-end lab script (Linux / macOS / WSL)
├── run-lab.ps1               # Automated end-to-end lab script (Windows PowerShell)
└── README.md                 # Project documentation and hands-on guide
```

---

## Prerequisites

Before starting, ensure you have the following tools installed:

| Tool | Recommended Version | Purpose |
| :--- | :--- | :--- |
| [Docker](https://docs.docker.com/get-docker/) | `>= 24.0` | Container runtime engine |
| [Kind](https://kind.sigs.k8s.io/) | `>= 0.20` | Local multi-node Kubernetes cluster management |
| [kubectl](https://kubernetes.io/docs/tasks/tools/) | `>= 1.28` | Kubernetes CLI |
| [Helm](https://helm.sh/) | `>= 3.12` | Kubernetes package manager for Kyverno installation |
| [Kyverno CLI](https://kyverno.io/docs/kyverno-cli/) | `>= 1.12` | *(Optional)* Offline policy testing in CI/CD |

---

## Quick Start (Automated Lab)

If you have all prerequisites installed and Docker running, you can execute the entire lab end-to-end (cluster creation, Kyverno installation, policy deployment, and positive/negative testing) using a single command:

### Linux / macOS / WSL
```bash
chmod +x run-lab.sh
./run-lab.sh
```

### Windows (PowerShell)
```powershell
.\run-lab.ps1
```

### Script Actions & Subcommands
Both scripts support granular subcommands:
- `all` (default): Runs prerequisite checks, provisions the cluster, installs Kyverno, deploys all policies, and executes tests.
- `up`: Provisions the Kind cluster and installs Kyverno + all security policies.
- `test`: Executes positive and negative policy admission tests against the active cluster.
- `down`: Cleans up test pods, removes policies, and destroys the Kind cluster.

*Example on Linux/macOS:*
```bash
./run-lab.sh test    # Run only policy tests
./run-lab.sh down    # Tear down cluster and cleanup
```

*Example on Windows:*
```powershell
.\run-lab.ps1 -Action test   # Run only policy tests
.\run-lab.ps1 -Action down   # Tear down cluster and cleanup
```

---

## Step-by-Step Lab Walkthrough

### 1. Provision Local Cluster with Kind

The repository includes a ready-to-use Kind cluster configuration file named `kind-config.yaml` to set up a multi-node cluster (1 control plane, 1 worker):

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
```

Spin up the cluster:

```bash
kind create cluster --config kind-config.yaml --name kyverno-lab
```

Verify that the cluster is healthy and nodes are in `Ready` state:

```bash
kubectl cluster-info --context kind-kyverno-lab
kubectl get nodes
```

---

### 2. Install Kyverno via Helm

Add the official Kyverno Helm repository:

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
```

Install Kyverno into its own dedicated namespace (`kyverno`):

```bash
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace
```

---

### 3. Verify Kyverno Deployment

Wait until all Kyverno controller pods are running and ready:

```bash
kubectl wait --namespace kyverno \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/part-of=kyverno \
  --timeout=120s
```

Check the pods and Custom Resource Definitions (CRDs):

```bash
kubectl get pods -n kyverno
kubectl get crd | grep kyverno
```

You should see controllers running (admission controller, background controller, reports controller) and the `clusterpolicies.kyverno.io` CRD registered.

---

### 4. Deploy the Security Policies

Apply both the resource limits policy and the privileged container restriction policy:

```bash
kubectl apply -f require-limits.yaml
kubectl apply -f restrict-privilege.yaml
```

Verify that both cluster policies are installed and ready:

```bash
kubectl get clusterpolicy
```

*Expected output:*
```plaintext
NAME                              ADMISSION   BACKGROUND   READY   AGE   MESSAGE
require-cpu-memory-limits         true        true         true    10s   Ready
restrict-privileged-containers    true        true         true    10s   Ready
```

---

### 5. Test Policy Enforcement

#### Negative Test 1: Reject Pod Without Limits

Attempt to deploy `bad-pod.yaml`, which does not specify `resources.limits`:

```bash
kubectl apply -f bad-pod.yaml
```

**Expected Result (Admission Blocked):**
The admission webhook intercepts the request and blocks pod creation with a clear error:

```plaintext
Error from server: error when creating "bad-pod.yaml": admission webhook "validate.kyverno.svc-fail" denied the request: 

resource Pod/default/test-pod-bad was blocked due to the following policies 

require-cpu-memory-limits:
  check-cpu-memory-limits: 'validation error: CPU and memory resource limits are required
    for all containers. rule check-cpu-memory-limits failed at path /spec/containers/0/resources/limits/'
```

Confirm that the pod was **not** created:

```bash
kubectl get pod test-pod-bad
# Error from server (NotFound): pods "test-pod-bad" not found
```

---

#### Negative Test 2: Reject Privileged Container

Attempt to deploy `bad-pod-priv.yaml`, which requests `securityContext.privileged: true`, root privileges, and a host filesystem mount:

```bash
kubectl apply -f bad-pod-priv.yaml
```

**Expected Result (Admission Blocked):**
The Kyverno admission controller identifies the privileged container request and rejects it:

```plaintext
Error from server: error when creating "bad-pod-priv.yaml": admission webhook "validate.kyverno.svc-fail" denied the request: 

resource Pod/default/test-pod-hacker-priv was blocked due to the following policies 

restrict-privileged-containers:
  validate-privileged: 'validation error: Privileged mode is prohibited. Containers
    must not request securityContext.privileged: true. rule validate-privileged failed at path /spec/containers/0/securityContext/privileged/'
```

Confirm that the privileged pod was **not** created:

```bash
kubectl get pod test-pod-hacker-priv
# Error from server (NotFound): pods "test-pod-hacker-priv" not found
```

---

#### Positive Test: Accept Compliant Pod

Deploy `good-pod.yaml`, which explicitly sets `requests` and `limits` and runs in standard unprivileged mode:

```bash
kubectl apply -f good-pod.yaml
```

**Expected Result (Admission Allowed):**

```plaintext
pod/test-pod-good created
```

Verify the pod is running and inspect its allocated resources:

```bash
kubectl get pod test-pod-good
kubectl get pod test-pod-good -o jsonpath='{.spec.containers[*].resources}'
```

---

## Policy Deep Dive: ClusterPolicy

### Policy 1: Require Resource Limits (require-limits.yaml)

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/kyverno.io/clusterpolicy_v1.json
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-cpu-memory-limits
  annotations:
    policies.kyverno.io/title: Require CPU and Memory Limits
    policies.kyverno.io/category: Best Practices
    policies.kyverno.io/severity: medium
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/description: >-
      Containers without resource limits can monopolize cluster resources and
      affect other workloads. This policy ensures all containers, init containers,
      and ephemeral containers define CPU and memory limits.
spec:
  validationFailureAction: Enforce  # Blocks non-compliant admission requests (can also be 'Audit')
  background: true                  # Evaluates existing cluster resources in background scans
  rules:
    - name: check-cpu-memory-limits
      match:
        any:
          - resources:
              kinds:
                - Pod              # Matches Pod resources during CREATE and UPDATE
      validate:
        message: "CPU and memory resource limits are required for all containers."
        pattern:
          spec:
            containers:
              - resources:
                  limits:
                    cpu: "?*"      # Requires a non-empty CPU limit
                    memory: "?*"   # Requires a non-empty memory limit
            =(initContainers):
              - resources:
                  limits:
                    cpu: "?*"
                    memory: "?*"
            =(ephemeralContainers):
              - resources:
                  limits:
                    cpu: "?*"
                    memory: "?*"
```

---

### Policy 2: Restrict Privileged Containers (restrict-privilege.yaml)

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/kyverno.io/clusterpolicy_v1.json
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-privileged-containers
  annotations:
    policies.kyverno.io/title: Restrict Privileged Containers
    policies.kyverno.io/category: Pod Security Standards (Baseline)
    policies.kyverno.io/severity: high
    policies.kyverno.io/description: >-
      Privileged mode disables security mechanisms and grants full access to the host node. 
      This policy blocks any pod attempting to run in privileged mode.
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: validate-privileged
      match:
        any:
          - resources:
              kinds:
                - Pod
      validate:
        message: "Privileged mode is prohibited. Containers must not request securityContext.privileged: true."
        pattern:
          spec:
            containers:
              - =(securityContext):
                  =(privileged): "false"
```

### Key Policy Components

1. **`apiVersion: kyverno.io/v1` & `kind: ClusterPolicy`**:
   - The production standard Kyverno resource definition, fully recognized by Kubernetes and IDE validation schemas.
2. **`validationFailureAction: Enforce`**:
   - `Enforce` rejects non-compliant requests at admission time.
   - For initial rollout on live clusters, setting this to `Audit` allows reporting violations in PolicyReports without blocking deployments.
3. **Pattern Matching (`pattern`)**:
   - Kyverno uses declarative pattern matching to verify the structure of Kubernetes manifests.
   - In `restrict-privilege.yaml`, the existence anchor `=(securityContext)` checks if `securityContext` is defined; if present, `=(privileged)` must be `false`.
4. **Conditional Anchors (`=(initContainers)`, `=(ephemeralContainers)`)**:
   - The parentheses `=(...)` denote an *existence anchor*.
   - If `initContainers` or `ephemeralContainers` are present in the Pod spec, Kyverno enforces rules on them as well. If they are absent, the check passes.

---

## Testing with Kyverno CLI (Shift-Left / CI/CD)

You can validate manifests against Kyverno policies locally or in continuous integration pipelines without deploying a live Kubernetes cluster:

```bash
# Test resource limit enforcement
kyverno apply require-limits.yaml --resource bad-pod.yaml      # Fails (missing limits)
kyverno apply require-limits.yaml --resource good-pod.yaml     # Passes

# Test privileged container restriction
kyverno apply restrict-privilege.yaml --resource bad-pod-priv.yaml  # Fails (privileged: true)
kyverno apply restrict-privilege.yaml --resource good-pod.yaml      # Passes
```

---

## Troubleshooting & Verification

- **Check Kyverno Controller Logs:**
  ```bash
  kubectl logs -n kyverno -l app.kubernetes.io/name=kyverno -f
  ```
- **Inspect Policy Reports:**
  ```bash
  kubectl get clusterpolicyreport -A
  kubectl describe clusterpolicyreport
  ```
- **Check Validating Webhook Configurations:**
  ```bash
  kubectl get validatingwebhookconfigurations
  ```

---

## Cleanup

When finished with the lab, clean up deployed pods or tear down the entire Kind cluster:

```bash
# Using the automated script:
./run-lab.sh down          # Linux / macOS / WSL
.\run-lab.ps1 -Action down # Windows PowerShell

# Or manually:
kubectl delete pod test-pod-good test-pod-bad test-pod-hacker-priv --ignore-not-found
kubectl delete -f require-limits.yaml --ignore-not-found
kubectl delete -f restrict-privilege.yaml --ignore-not-found
kind delete cluster --name kyverno-lab
```

---

## Best Practices & Next Steps

1. **Enforce Requests alongside Limits:** Prevent node overcommitment by pairing limits with guaranteed requests.
2. **Disallow Privileged Containers:** Ensure `securityContext.privileged: false` is enforced across all workloads.
3. **Prevent Root Users:** Require containers to run as non-root (`runAsNonRoot: true`).
4. **Disallow `:latest` Image Tags:** Enforce immutable image tags or SHA256 digests in manifests.
5. **Gradual Rollout:** Deploy new policies with `validationFailureAction: Audit` first to assess impact before switching to `Enforce`.

---

## License

This project is licensed under the MIT License.
