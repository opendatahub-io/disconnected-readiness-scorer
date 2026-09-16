## Description

All container image references in RHOAI component repos must use immutable `@sha256:` digest references instead of mutable tags (`:latest`, `:v1.2`, etc.). In disconnected deployments, the mirror registry is populated once during installation. If a tag resolves to a different digest than what was mirrored, the image pull will fail or — worse — silently pull an older version. Digest references guarantee that exactly the mirrored image is deployed.

This rule is evaluated by the [disconnected-readiness-scorer](https://github.com/opendatahub-io/disconnected-readiness-scorer) static analysis tool. It scans source code and manifest files for image references that use tags instead of digests.

## What the Check Verifies

The rule scans `.go`, `.py`, `.yaml`, `.yml`, `.json`, `.toml` files and Dockerfiles for three patterns:

| Pattern | Description | Example |
|---------|-------------|---------|
| **Qualified image with tag** | `registry/org/name:tag` without `@sha256:` | `quay.io/org/image:v1.2.3` |
| **OCI URI without digest** | `oci://` URI missing `@sha256:` pin | `oci://registry.io/chart:1.0` |
| **Unqualified k8s image** | `image: name:tag` in YAML `image:` fields | `image: nginx:latest` |

Only git-tracked files are scanned. Files larger than 512 KB are skipped. Package-manager metadata files (`package.json`, npm/pnpm lockfiles, and `pnpm-workspace.yaml`) are excluded to avoid false positives from npm package references. HTTP/HTTPS URLs are not treated as image references.

Source code files (`.go`, `.py`, `.sh`) receive an additional annotation noting the image is hardcoded in source, making it harder to update centrally.

Files managed by the params.env + kustomize pattern (`params.env` files) produce info-level findings instead of blockers, since those images are managed centrally through the kustomize pipeline. Findings in non-production kustomize overlays are also downgraded to info.

## Common Failures

| Failure | Severity | Example |
|---------|----------|---------|
| YAML manifest with tagged image | blocker | `image: quay.io/org/controller:v2.1.0` |
| Dockerfile FROM with tag | blocker | `FROM registry.io/base:latest` |
| Go source with hardcoded tagged image | blocker | `DefaultImage = "quay.io/org/sidecar:v1"` |
| OCI Helm chart URI with tag | blocker | `oci://registry.io/charts/app:1.0` |
| Image in params.env with tag | info | `odh_component=quay.io/org/image:v1` |

## Guidance

### Step 1: Find the digest for the current tag

```bash
skopeo inspect docker://quay.io/org/image:v1.2.3 | jq -r '.Digest'
# Output: sha256:abc123def456...
```

Or using `crane`:

```bash
crane digest quay.io/org/image:v1.2.3
```

### Step 2: Replace the tag with a digest

Change:
```yaml
image: quay.io/org/image:v1.2.3
```

To:
```yaml
image: quay.io/org/image@sha256:abc123def456...
```

### Step 3: For params.env managed images

If the image is managed through params.env, update the value there — the kustomize pipeline propagates the digest to all rendered manifests:

```text
# params.env
odh_component=quay.io/org/image@sha256:abc123def456...
```

### Step 4: For hardcoded images in source code

Move the image reference to a configuration mechanism (environment variable, config file, or params.env) rather than hardcoding it in source:

```go
// Before (blocker — hardcoded tag)
const DefaultImage = "quay.io/org/sidecar:v1"

// After (operator-injected digest)
image := os.Getenv("RELATED_IMAGE_SIDECAR")
if image == "" {
    image = "quay.io/org/sidecar@sha256:abc123..."
}
```

### False positives

Images in `params.env` files are already auto-downgraded to info severity — the release process resolves tags to digests in the Build-Config repos before they reach the CSV. Build-time images (Dockerfiles, CI scripts) that are never pulled on-cluster should be excepted. Non-image strings that happen to match the `registry/org/name:tag` pattern may occasionally trigger; add a path or message exception in [config/config.yaml](https://github.com/opendatahub-io/disconnected-readiness-scorer/blob/main/config/config.yaml) if confirmed safe.

## References

- [OCI image spec: digests](https://github.com/opencontainers/image-spec/blob/main/descriptor.md#digests)
- [Remediation guide](https://github.com/opendatahub-io/disconnected-readiness-scorer/blob/main/docs/remediation-guide.md#2-mutable-image-tags-no-image-tags) — investigation workflow and false positive identification
- [Rules reference](https://github.com/opendatahub-io/disconnected-readiness-scorer/blob/main/docs/rules-reference.md#rule-no-image-tags) — implementation details
- [Rule source](https://github.com/opendatahub-io/disconnected-readiness-scorer/blob/main/rules/no_image_tags.py)
