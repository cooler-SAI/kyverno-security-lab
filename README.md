# Kyverno Security Lab

A practical hands-on lab for managing Kubernetes cluster security using Policy-as-Code with Kyverno.

## Project Goals
- Declarative security policies without writing Go code.
- Validation and mutation of manifests during Admission Review.
- Integration with a local Kubernetes cluster using Kind (Kubernetes in Docker).

---

## Prerequisites

Before starting, ensure you have the following tools installed on your local machine:
- [Docker](https://docs.docker.com/get-docker/)
- [Kind](https://kind.sigs.k8s.io/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [Helm](https://helm.sh/) (optional, but recommended)

---

## Quick Start Guide

### 1. Create a Local Kubernetes Cluster with Kind
Create a cluster configuration file named `kind-config.yaml` to set up your test cluster:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
