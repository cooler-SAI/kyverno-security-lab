# Kyverno Security Lab

A hands-on, practical lab for implementing Kubernetes cluster security and governance using Policy-as-Code with **Kyverno**. This project demonstrates policy enforcement using the standard, Kubernetes-native Kyverno `ClusterPolicy` (`kyverno.io/v1`).

---

## Table of Contents

- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Step-by-Step Lab Walkthrough](#step-by-step-lab-walkthrough)
  - [1. Provision Local Cluster with Kind](#1-provision-local-cluster-with-kind)
  - [2. Install Kyverno via Helm](#2-install-kyverno-via-helm)
  - [3. Verify Kyverno Deployment](#3-verify-kyverno-deployment)
  - [4. Deploy the Security Policy](#4-deploy-the-security-policy)
  - [5. Test Policy Enforcement](#5-test-policy-enforcement)
    - [Negative Test: Reject Pod Without Limits](#negative-test-reject-pod-without-limits)
    - [Positive Test: Accept Compliant Pod](#positive-test-accept-compliant-pod)
- [Policy Deep Dive: ClusterPolicy](#policy-deep-dive-clusterpolicy)
- [Testing with Kyverno CLI (Shift-Left / CI/CD)](#testing-with-kyverno-cli-shift-left--cicd)
- [Troubleshooting & Verification](#troubleshooting--verification)
- [Cleanup](#cleanup)
- [Best Practices & Next Steps](#best-practices--next-steps)

---

## Project Overview

In multi-tenant or production Kubernetes environments, uncontrolled container workloads can cause resource exhaustion (noisy neighbors, CPU throttling, or Out-Of-Memory / OOM-kills) that degrades node reliability. 

This lab demonstrates how to enforce mandatory CPU and memory resource limits across all container types (standard containers, init containers, and ephemeral containers) using Kyverno before any pod is scheduled onto a node.

### Why Kyverno?
- **Kubernetes-Native:** Written in declarative YAML — no custom domain-specific languages (DSLs) like Rego or Go programming required.
- **Pattern Matching:** Simple, intuitive declarative patterns to validate Kubernetes object structures.
- **Flexible Actions:** Supports both auditing (`Audit`) and active admission enforcement (`Enforce`).
- **Comprehensive Lifecycle:** Validates, mutates, generates, and cleans up Kubernetes resources.

---

## Key Features

- **Policy-as-Code:** Declarative policy definitions managed under version control.
- **Standard CRD:** Uses the production-standard `kyverno.io/v1` `ClusterPolicy` resource.
- **Comprehensive Container Coverage:** Evaluates `spec.containers`, `spec.initContainers`, and `spec.ephemeralContainers`.
- **Shift-Left Ready:** Policies and manifests can be validated in CI/CD pipelines before deployment to clusters.

---

## Repository Structure

```plaintext
kyverno-security-lab/
├── require-limits.yaml   # Kyverno ClusterPolicy enforcing CPU & memory limits
├── bad-pod.yaml          # Negative test case (violates policy, missing limits)
├── good-pod.yaml         # Positive test case (conforms to policy, limits defined)
└── README.md             # Project documentation and hands-on guide
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

## Step-by-Step Lab Walkthrough

### 1. Provision Local Cluster with Kind

Create a Kind cluster configuration file named `kind-config.yaml` to set up a multi-node cluster (1 control plane, 1 worker):

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

### 4. Deploy the Security Policy

Apply the `require-limits.yaml` policy manifest to the cluster:

```bash
kubectl apply -f require-limits.yaml
```

Verify that the cluster policy is installed and ready:

```bash
kubectl get clusterpolicy
```

*Expected output:*
```plaintext
NAME                         ADMISSION   BACKGROUND   READY   AGE   MESSAGE
require-cpu-memory-limits    true        true         true    10s   Ready
```

---

### 5. Test Policy Enforcement

#### Negative Test: Reject Pod Without Limits

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

#### Positive Test: Accept Compliant Pod

Deploy `good-pod.yaml`, which explicitly sets both `requests` and `limits` for CPU and memory:

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

Below is the annotated `require-limits.yaml` policy:

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

### Key Policy Components

1. **`apiVersion: kyverno.io/v1` & `kind: ClusterPolicy`**:
   - The production standard Kyverno resource definition, fully recognized by Kubernetes and IDE validation schemas.
2. **`validationFailureAction: Enforce`**:
   - `Enforce` rejects non-compliant requests at admission time.
   - For initial rollout on live clusters, setting this to `Audit` allows reporting violations in PolicyReports without blocking deployments.
3. **Pattern Matching (`pattern`)**:
   - Kyverno uses declarative pattern matching to verify the structure of Kubernetes manifests.
   - `?*` is a wildcard ensuring the field exists and contains at least one character.
4. **Conditional Anchors (`=(initContainers)`, `=(ephemeralContainers)`)**:
   - The parentheses `=(...)` denote an *existence anchor*.
   - If `initContainers` or `ephemeralContainers` are present in the Pod spec, Kyverno enforces CPU and memory limits on them as well. If they are absent, the check passes.

---

## Testing with Kyverno CLI (Shift-Left / CI/CD)

You can validate manifests against Kyverno policies locally or in continuous integration pipelines without deploying a live Kubernetes cluster:

```bash
# Test the bad pod (should fail)
kyverno apply require-limits.yaml --resource bad-pod.yaml

# Test the compliant pod (should pass)
kyverno apply require-limits.yaml --resource good-pod.yaml
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
# Delete test pods
kubectl delete pod test-pod-good --ignore-not-found

# Delete policy
kubectl delete -f require-limits.yaml --ignore-not-found

# Delete Kind cluster
kind delete cluster --name kyverno-lab
```

---

## Best Practices & Next Steps

1. **Enforce Requests alongside Limits:** Prevent node overcommitment by pairing limits with guaranteed requests.
2. **Disallow Privileged Containers:** Ensure `securityContext.privileged: false` is enforced.
3. **Prevent Root Users:** Require containers to run as non-root (`runAsNonRoot: true`).
4. **Disallow `:latest` Image Tags:** Enforce immutable image tags or SHA256 digests in manifests.
5. **Gradual Rollout:** Deploy new policies with `validationFailureAction: Audit` first to assess impact before switching to `Enforce`.

---

## License

This project is licensed under the MIT License.
