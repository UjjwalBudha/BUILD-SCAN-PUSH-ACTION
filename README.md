# Build, Scan, and Push Docker Images Action

A GitHub Action that builds Docker images, performs security scans using Trivy, and optionally pushes them to a container registry.

## Overview

This action is a thin wrapper around [docker/build-push-action](https://github.com/docker/build-push-action) that adds security scanning capabilities. It provides a seamless workflow for:

1. Building Docker images
2. Scanning for vulnerabilities using Trivy
3. Pushing images to a container registry
4. Signing images using Cosign and GitHub OIDC tokens

## Features

- 🔒 **Security Scanning**
  - Trivy vulnerability scanning with configurable severity levels

- 🔄 **Full Build Pipeline**
  - All capabilities of docker/build-push-action
  - Support for multi-platform builds
  - Caching support for faster builds

- 📦 **Registry Integration**
  - Push to any container registry
  - SBOM generation
  - Provenance attestation

- ✅ **Supply Chain Security**
  - Automatic image signing with Cosign and GitHub OIDC

## Usage

Add this action to your workflow file:

```yaml
jobs:
  build-and-push:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write # needed for signing the images with GitHub OIDC Token
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Login to container registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Build, scan and push
        uses: UjjwalBudha/BUILD-SCAN-PUSH-ACTION@v1
        with:
          context: .
          push: true
          tags: ghcr.io/myorg/myimage:latest
          trivy-severity: "HIGH,CRITICAL"
```

## Inputs

### Build Configuration

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `context` | Build's context (PATH or URL) | No | |
| `file` | Path to the Dockerfile | No | |
| `build-args` | List of build-time variables | No | |
| `tags` | List of tags | No | |
| `labels` | List of metadata for an image | No | |
| `target` | Set the target build stage to build | No | |
| `platforms` | List of target platforms for build | No | |

### Cache Configuration

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `cache-from` | List of external cache sources | No | |
| `cache-to` | List of cache export destinations | No | |

### Security Scanning

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `trivy-enabled` | Enable scanning with Trivy | No | `true` |
| `trivy-severity` | Comma-separated list of vulnerability severities to scan for | No | `HIGH,CRITICAL` |
| `trivy-exit-code` | Exit code when vulnerabilities were found | No | `1` |

### Push Configuration

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `push` | Push to registry (shorthand for --output=type=registry) | No | `false` |
| `load` | Load to docker (shorthand for --output=type=docker) | No | `false` |
| `sbom` | Generate SBOM attestation | No | |
| `provenance` | Generate provenance attestation | No | `false` |

### Secrets

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `secrets` | List of secrets to expose to the build | No | |
| `secret-envs` | List of secret env vars to expose to the build | No | |

## Outputs

| Name | Description |
|------|-------------|
| `imageid` | Image ID |
| `digest` | Image digest |
| `metadata` | Build result metadata |

## Security Features

### Trivy Vulnerability Scanning

The action scans for vulnerabilities using Trivy. You can configure:
- Which severity levels to scan for (`trivy-severity`)
- Whether to fail the build if vulnerabilities are found (`trivy-exit-code`)

### Image Signing

When `push` is set to `true`, the action automatically signs the images using Cosign with GitHub OIDC tokens. This adds a layer of trust and verification to your container images.

## License

MIT

## Author

[ujwalbudha](https://github.com/ujwalbudha)
