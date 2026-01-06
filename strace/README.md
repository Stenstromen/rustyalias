# Strace Setup for Seccomp Profile Generation

This directory contains the necessary files to generate a seccomp profile using strace in a kind cluster.

## Prerequisites

- Podman
- kind (Kubernetes in Docker) with experimental Podman provider
- kubectl

## Setup Instructions

### 1. Set the Kind provider to Podman

```bash
export KIND_EXPERIMENTAL_PROVIDER=podman
```

### 2. Build the strace image with Podman

```bash
podman build -t rustyalias-strace:latest -f strace/Dockerfile .
```

### 3. Create the kind cluster

```bash
cd strace
kind create cluster --name rustyalias-strace --config kind-config.yaml
```

### 4. Load the image into kind

Save the image as an OCI archive and load it into the kind cluster:

```bash
# Save the image as an OCI archive
podman save --format oci-archive -o rustyalias-strace.tar rustyalias-strace:latest

# Load the image archive into kind
kind load image-archive rustyalias-strace.tar --name rustyalias-strace
```

### 5. Deploy the application with strace

```bash
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```
