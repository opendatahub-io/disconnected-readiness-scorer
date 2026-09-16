# Rules Reference

This document describes each rule in the Disconnected Readiness Scorer, including what it scans, how it determines severity, and how it interacts with other components.

## Table of Contents

- [Shared Infrastructure](#shared-infrastructure)
- [Rule: image-manifest-complete (alias: csv)](#rule-image-manifest-complete)
- [Rule: no-image-tags (alias: tags)](#rule-no-image-tags)
- [Rule: no-runtime-egress (alias: egress)](#rule-no-runtime-egress)
- [Rule: python-imports-bundled (alias: python)](#rule-python-imports-bundled)
- [Rule: params-env-wiring (alias: params_env)](#rule-params-env-wiring)
- [Rule: operator-manifest (alias: manifest)](#rule-operator-manifest)
- [Production Scope](#production-scope)
- [Orchestrator Flow](#orchestrator-flow)

---

## Shared Infrastructure

**File:** `rules/common.py`

Provides the core types and utilities used by all rules:

- **`Severity`** — Enum with two values: `blocker` and `info`.
- **`Finding`** — Dataclass with fields: `severity`, `file`, `line`, `image`, `message`. The `__post_init__` method validates that `severity` is a valid `Severity` value, raising `ValueError` otherwise.
- **`RuleResult`** — Dataclass with fields: `rule` (name), `passed` (bool, default `True`), `findings` (list of `Finding`), `files_checked` (list of relative file paths for verbose output).
- **`ProductionScope`** — Dataclass with fields: `method`, `manifest_files`, `manifest_source`, `overlay_paths`, `production_dirs`, `production_files`.

Key utility functions:

| Function | Purpose |
|----------|---------|
| `get_tracked_files(repo_root)` | Returns a set of resolved `Path` objects from `git ls-files -z`. Rules use this to skip untracked files. |
| `is_file_in_production_scope(filepath, scope)` | Returns `True` (in scope), `False` (out of scope), or `None` (scope not computed). Checks `production_dirs` and `production_files`. |
| `is_yaml_in_production_scope(filepath, scope)` | Checks if a YAML file is in the `manifest_files` set. |
| `build_overlay_file_map(arch_data, repo_root)` | Builds a dict mapping kustomize overlay identifiers to sets of file paths using arch-analyzer's `kustomize_components` data. |
| `is_non_production_overlay_file(filepath, scope, overlay_map)` | Returns `True` if the file belongs to a kustomize overlay that is not in the operator's deployed `overlay_paths`. |
| `downgrade_non_production_overlay(severity, msg, filepath, scope, overlay_map)` | Shared helper used by `no-image-tags` and `image-manifest-complete`: if severity is `blocker` and the file is a non-production overlay, returns `info` with a `[non-production overlay]` message suffix. |
| `find_params_env_dirs(repo_root)` | Finds all directories containing both `params.env` and `kustomization.yaml`. |
| `detect_image_pattern(repo_root)` | Detects whether the repo uses `RELATED_IMAGE_*` env vars (`env_var`) or static CSV `relatedImages` (`static_csv`). Shared by `image-manifest-complete` and `no-image-tags` — both need to know this before deciding whether to request the operator manifest. |

**Skip directories** (global): `.git`, `vendor`, `node_modules`, `__pycache__`, `.tox`, `.devcontainer`

**Dual-import pattern:** Every rule uses `try: from rules.common import ... / except ModuleNotFoundError: from common import ...` so that standalone execution (`python3 rules/foo.py .`) works without the package being installed. The catch is deliberately narrow (`ModuleNotFoundError`, not `ImportError`) to avoid masking symbol or circular import errors.

---

## Rule: image-manifest-complete

| | |
|---|---|
| **Alias** | `csv` |
| **File** | `rules/image_manifest_complete.py` |
| **Entry point** | `run(repo_root, manifest_env_vars=None, production_scope=None, arch_data=None, non_image_prefixes=None, **_kwargs) -> RuleResult` |
| **Scanned files** | `.go`, `.py`, `.yaml`, `.yml`, `.json`, `.sh`, `Dockerfile` |
| **Filters** | Git-tracked files only; skips params.env directories; skips files outside production scope |
| **External deps** | PyYAML (for CSV pattern parsing) |

### What it does

Checks that every container image reference in the repository is accounted for in the disconnected image manifest. See the [reference doc](references/image-manifest-complete.md) for user-facing guidance, severity classification, and remediation examples.

### Detection logic

**Step 1 — Pattern detection** (`detect_image_pattern()`):

1. Counts `RELATED_IMAGE_*` occurrences in `.go` files. If ≥ 5 matches are found, the repo uses the **env_var** pattern.
2. Otherwise, searches `.yaml` files for `relatedImages:` combined with `ClusterServiceVersion`. If found, the repo uses the **static_csv** pattern.
3. If neither is detected, returns `unknown`.

**Step 2 — Image extraction** (`scan_for_image_refs()`):

Two regex patterns extract image references from source lines:
- `IMAGE_REF_PATTERN` — matches `image:`, `newName:`, `imageUrl:`, `FROM` directives followed by a registry/repo/name reference.
- `GO_IMAGE_ASSIGN_PATTERN` — matches Go string assignments with strict registry format (requires a dot in the domain).

Non-registry domains are filtered out: `github.com`, `gitlab.com`, `golang.org`, `k8s.io`, `sigs.k8s.io`, etc. Comment lines (`//`, `#`) are skipped.

**Step 3 — Validation** (three paths based on detected pattern):

**A) env_var pattern** (`check_env_var_pattern()`):
- Extracts all `RELATED_IMAGE_*` env var names from Go source.
- For each image reference found in the repo, checks whether the same line contains a `RELATED_IMAGE_*` variable name.
- If no same-line match, checks whether the file or sibling Go files in the same directory define `RELATED_IMAGE_*` vars.
- If the image has no mapping at all, it produces a **blocker** ("will not be mirrored").
- When `manifest_env_vars` is provided (from the operator manifest), cross-references: vars in the repo but not in the manifest are **blocker**; manifest vars not referenced in the repo are **info**.

**B) static_csv pattern** (`check_static_csv_pattern()`):
- Parses `relatedImages` entries from ClusterServiceVersion YAML documents.
- Normalizes image refs (strips tags and digests) for comparison.
- Images found in source but not in the CSV list produce a **blocker**.

**C) unmanaged images** (`check_unmanaged_images()`):
- Used when no RELATED_IMAGE pattern is detected but `manifest_env_vars` is provided (repo is operator-managed).
- Every hardcoded image reference produces a **blocker**.

### Severity summary

| Finding | Severity |
|---------|----------|
| Image with no RELATED_IMAGE mapping | blocker |
| Image not in CSV relatedImages | blocker |
| Env var in repo but not in operator manifest | blocker |
| Var referenced by env var name not in manifest | blocker |
| Non-production overlay file | info (downgraded) |
| Image covered by file/sibling RELATED_IMAGE var | info |
| Manifest vars not referenced in repo | info |

---

## Rule: no-image-tags

| | |
|---|---|
| **Alias** | `tags` |
| **File** | `rules/no_image_tags.py` |
| **Entry point** | `run(repo_root, manifest_env_vars=None, production_scope=None, arch_data=None, non_image_prefixes=None, **_kwargs) -> RuleResult` |
| **Scanned files** | `.go`, `.py`, `.yaml`, `.yml`, `.json`, `.toml` |
| **Filters** | Git-tracked only; skips package-manager metadata (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `package.json`); skips files > 512 KB; skips params.env directories; skips files outside production scope |
| **External deps** | None |

### What it does

Enforces `@sha256:` digest pinning on all image references. See the [reference doc](references/no-image-tags.md) for user-facing guidance, severity classification, and remediation examples.

### Detection logic

Two regex patterns scan each line:

1. **`IMAGE_REF_PATTERN`** — Matches qualified image references: `[protocol://]registry/repo/name[:tag|@digest]`. HTTP URLs are skipped. Images with `@sha256:` are accepted. Images with no tag/digest suffix are skipped (only refs with an explicit `:tag` are flagged). OCI URIs (`oci://`) are handled separately — they must also have `@sha256:` pinning.

2. **`K8S_UNQUALIFIED_IMAGE`** — YAML-specific pattern matching `image: name:tag` on a single line (unqualified images without a registry). Only checked in `.yaml`/`.yml` files and only on lines not already matched by the first pattern.

### Severity logic

Ordered stages (see `rules/no_image_tags.py` module docstring). Stages 1–4 run in `_emit_finding`; stage 0 and stage 5 run in `run()`:

0. Files outside production scope → **skipped** (no finding).
1. Images in `params.env` → **info** (excluded file, handled by the params_env rule).
2. Images in non-production kustomize overlays → **info** (`downgrade_non_production_overlay`, `[non-production overlay]`).
3. Tagged matches on YAML lines belonging to OpenAPI-style documentation fields (`description` / `example` / `examples`, via `documentation_field_lines()` in `rules/yaml_documentation_fields.py`) → **info** (`[documentation field]`). Schema keywords `default` / `enum` / `const` never inherit docs status from an ancestor docs key.
4. Remaining tagged images → **blocker**, with additional context:
   - Source code files (`.go`, `.py`, `.ts`, `.sh`): "Hardcoded in source code."
   - Manifest files: "Manifest file not managed by params.env."
   - OCI URIs: specific message about missing digest pin.
5. When `manifest_env_vars` is set, remaining **blocker** findings may become **info** via the RELATED_IMAGE post-pass (below).

### Manifest cross-reference downgrade

When `manifest_env_vars` is provided (from the operator manifest, same as `image-manifest-complete`), a blocker is downgraded to **info** if a confirmed `RELATED_IMAGE_*` var already covers the image:

- **Source code files** (`is_source_code()` — `.go`, `.py`, `.ts`, `.tsx`, `.sh`): the var must be textually inside the same balanced-paren block as the image, in the same file, possibly spanning multiple lines, with any trailing line comment inside that block stripped before matching. This is any balanced parenthesized span — typically a function call, but the scanner has no syntactic awareness of call expressions specifically, so an `if (...)` condition or a tuple is matched the same way. Found via a plain paren-position-tracking scan (no AST parser, no tree-sitter): the block enclosing the image's exact `(line, column)` position is the innermost pair of matching parentheses that contains it, and the matched text is trimmed to the exact open/close paren columns — text before the open paren or after the close paren on those two lines is never included. Single- and double-quoted strings are scanned per line; backtick strings (Go raw strings, TS/TSX template literals) and Python triple-quoted strings can span multiple lines, so their state is tracked across lines. A resolved block spanning more than 80 lines is treated as unresolved (falls back to same-line only), since a span that large signals a probable mis-parse.
- **Non-source files** (YAML, `params.env`, JSON, TOML): same-line only — there is no call-expression concept in those formats.
- **No whole-file and no cross-file matching at all.** A var declared elsewhere in the file, or in a different (e.g. sibling) file, is never treated as coverage for this rule.
- When the same image text appears more than once on one line (e.g. two independent calls sharing the same literal), each finding resolves against its own occurrence, not all against the first one.

This is deliberately **stricter** than `image-manifest-complete`'s own same-line → whole-file → sibling-`.go`-file lookup (see "Detection logic" → "A) env_var pattern" in its rule section above), which is unchanged. A review found that reusing that coarser lookup for `no-image-tags` produced false negatives — an unrelated var anywhere in the file, or in a sibling file, being treated as "covering" an unrelated image — because downgrading a `no-image-tags` finding cancels a different rule's independently-detected tag-mutability defect outright, not just an internal annotation the way it does inside `image-manifest-complete` itself. The two rules do not share this decision logic; `no_image_tags.py`'s balanced-paren block detection is private to that module.

**Known limitations:**

- **RELATED_IMAGE matching:** a block containing more than one image reference or more than one `RELATED_IMAGE_*` var (e.g. a call with several arguments, or nested calls sharing an outer block) can still associate the wrong var with the wrong image — exact per-argument correspondence needs real parsing and is out of scope. A `RELATED_IMAGE_*` var name appearing inside an unrelated string literal within the same block (not the intended argument) is still treated as confirmed coverage — only trailing comments are stripped before matching, not string contents, since the intended var reference is itself normally a string literal; distinguishing "the string this rule expects" from "some other string that happens to contain the same text" needs real per-argument parsing too.
- **Documentation-field line granularity:** docs detection records whole line numbers, matching the line-based image regex scan. A real `image:` key that shares a physical line with a `description` / `example` / `examples` key in flow-style YAML (e.g. `{description: "…", image: quay.io/evil:latest}`) is also downgraded to info. Idiomatic Kubernetes/CRD YAML is block-style, so this is rare; column-range tracking would close it.

---

## Rule: no-runtime-egress

| | |
|---|---|
| **Alias** | `egress` |
| **File** | `rules/no_runtime_egress.py` |
| **Entry point** | `run(repo_root, production_scope=None, **_kwargs) -> RuleResult` |
| **Scanned files** | `.go`, `.py`, `.ts`, `.tsx`, `.sh`, `.yaml`, `.yml` |
| **Filters** | Git-tracked only; skips files outside production scope |
| **External deps** | None |

### What it does

Detects outbound HTTP calls and network access in runtime source code that would fail in a disconnected environment. See the [reference doc](references/no-runtime-egress.md) for user-facing guidance, severity classification, and remediation examples.

### Detection patterns by language

**Go** (`.go`):
- `http.Get()`, `http.Post()`, `http.Head()`, `http.Do()`, `http.NewRequest()`
- `net.Dial()`
- `http.DefaultClient`
- `exec.Command("git")`

**Python** (`.py`):
- `requests.get/post/put/delete/head/patch()`
- `urllib.request.urlopen()`, `urllib.request.Request()`
- `httpx.get/post/put/delete()`, `httpx.AsyncClient()`
- `aiohttp.ClientSession()`
- `curl`/`wget` via subprocess
- HuggingFace: `from_pretrained()`, `snapshot_download()`, `load_dataset()`, `SentenceTransformer()`, `torch.hub.load()`
- HuggingFace CLI: `hf download`, `huggingface-cli download` via subprocess

**TypeScript** (`.ts`, `.tsx`):
- `fetch()`
- `axios.get/post/put/delete/request()`
- `http.request()`

**Shell** (`.sh`):
- `curl`, `wget`
- `hf download`, `huggingface-cli download`

**YAML manifests** (`.yaml`, `.yml`):

- `curl`, `wget` — catches inline shell commands in `command:`/`args:` fields of CronJob, Job, Pod, etc.
- `hf download`, `huggingface-cli download`

### Severity heuristic

Each match is classified by checking the surrounding line context:

1. **Always-network patterns** (e.g., HuggingFace downloads marked with `always_network=True`) → **blocker**
2. **Hardcoded external URL** — line contains `http://` or `https://` but no config indicators and not an internal URL → **blocker**
3. **Internal URL** — URL matches `kubernetes.default.svc`, `.svc.cluster.local`, `localhost`, `127.0.0.1`, `0.0.0.0`, or has a single-label hostname with no dots (e.g. `http://my-svc:8080/`) → **info**
4. **Configurable URL** — line contains config indicators (`os.Getenv`, `os.environ`, `config.`, `settings.`, `viper.`, `process.env`, `${`, etc.) → **info**
5. **No hardcoded URL** — pattern matched but no URL literal on the line → **info** (likely internal API call)

### Error handling

The `run()` function wraps execution in a try/except to prevent rule crashes from affecting the overall scoring. If the rule itself crashes, it produces a single blocker finding with the traceback.

---

## Rule: python-imports-bundled

| | |
|---|---|
| **Alias** | `python` |
| **File** | `rules/python_imports.py` |
| **Entry point** | `run(repo_root, **_kwargs) -> RuleResult` |
| **Scanned files** | `requirements*.txt`, `constraints*.txt`, `setup.py`, `pyproject.toml`, all `*.py` files |
| **Filters** | Git-tracked only; skips `.git`, `vendor`, `node_modules`, `__pycache__`, `.tox`, `venv`, `.venv` |
| **External deps** | None |

### What it does

Validates that Python dependencies are available from bundled or internal mirrors. See the [reference doc](references/python-imports-bundled.md) for user-facing guidance, severity classification, and remediation examples.

### Detection logic

**1. Requirements/constraints files** (`check_requirements_file()`):
- Scans `requirements*.txt` and `constraints*.txt` at any depth.
- `git+https://` dependencies → **blocker** ("requires internet at install time").
- Packages not in the known-bundled list → **info** ("verify availability in internal PyPI mirror"). Package names are normalized (lowercased, `-` and `.` replaced with `_`). Single-character package names are skipped.

**2. Runtime pip installs** (`check_runtime_pip_installs()`):
- Scans all `.py` files for `subprocess.*pip install` or `pip/pip3 install` patterns.
- Any match → **blocker** ("will fail without internet or internal mirror").

**3. Build config files**:
- Scans `setup.py` and `pyproject.toml` for `git+https://` dependencies.
- Any match → **blocker** ("git+https dependency in build config").

### Known-bundled packages

The rule maintains a hardcoded set of ~30 packages known to be commonly bundled in OpenShift-compatible environments: `numpy`, `pandas`, `scikit-learn`, `torch`, `tensorflow`, `transformers`, `flask`, `fastapi`, `requests`, `kubernetes`, `pytest`, etc. Packages not in this list produce informational findings only.

---

## Rule: params-env-wiring

| | |
|---|---|
| **Alias** | `params_env` |
| **File** | `rules/params_env.py` (logic), `rules/params_env_utils.py` (utilities) |
| **Entry point** | `run(repo_root, manifest_env_vars=None, production_scope=None, extra_filenames=None, **_kwargs) -> RuleResult` |
| **Scanned files** | `params.env`, `kustomization.yaml`, rendered kustomize manifests, `.go` files |
| **Filters** | Skips operator repos (detected by presence of `component-params-env.yaml`) |
| **External deps** | `kustomize` binary (required) |

### What it does

Validates the full `params.env` → kustomize → manifest → Go `os.Getenv` wiring chain. See the [reference doc](references/params-env-wiring.md) for user-facing guidance, severity classification, and remediation examples.

### Detection logic

**Step 1 — Overlay discovery:**
- Finds all directories containing both `params.env` (or custom filenames from central config) and `kustomization.yaml`.
- If `production_scope.manifest_source` is set, processes only that source folder.
- If `production_scope.overlay_paths` is set, filters to only operator-deployed overlays.

**Step 2 — Probe technique** (hardcoded image detection):
1. Creates a temporary copy of the overlay directory structure.
2. Replaces all `params.env` image values with the sentinel string `probe.test/verify-params-env:check`.
3. Runs `kustomize build` on the probe copy.
4. Any image in the rendered output that is NOT the sentinel → **blocker** ("hardcoded image not sourced from params.env").

**Step 3 — Wiring check** (on original overlays):
- Runs `kustomize build` on the original overlay.
- Extracts `configMapKeyRef` references and kustomize replacement keys from the rendered manifest.
- `params.env` keys not consumed by kustomize → **info** ("unused key").
- `configMapKeyRef` referencing a non-existent params.env key → **info**.

**Step 4 — Go env var cross-reference:**
- Scans all `.go` files for `os.Getenv("RELATED_IMAGE_*")` calls.
- `RELATED_IMAGE` vars in rendered manifests but not in Go code → **info** ("controller may ignore this image").
- Go code expects a var not in rendered manifests → **blocker** ("controller expects an image that won't be injected").

**Step 5 — Operator manifest cross-reference** (when `manifest_env_vars` is provided):
- `RELATED_IMAGE` vars mapped from params.env but not in operator manifest → **blocker**.
- Non-RELATED_IMAGE vars not in manifest → **info** ("may be stale").

### Key utilities (`params_env_utils.py`)

| Function | Purpose |
|----------|---------|
| `kustomize_available()` | Checks if `kustomize version` runs successfully |
| `kustomize_build(overlay_dir)` | Runs `kustomize build` with 120s timeout |
| `parse_params_env(path)` | Parses `KEY=VALUE` file, filters to image-like values (contains `/`, `:`, or `@`) |
| `discover_overlays(repo_root, filenames)` | Finds all overlay dirs with params.env + kustomization.yaml |
| `create_probe_overlay(overlay_dir, params_files, tmp, ignored)` | Creates temporary probe overlay with sentinel values |
| `extract_all_images(rendered, exclude_patterns)` | Extracts all image references from rendered manifest YAML |
| `extract_env_configmap_mappings(rendered)` | Maps env var names → configMap keys → ConfigMap names |
| `find_go_related_image_envs(repo_root)` | Scans .go files for `os.Getenv("RELATED_IMAGE_*")` patterns |

---

## Rule: operator-manifest

| | |
|---|---|
| **Alias** | `manifest` |
| **File** | `rules/operator_manifest.py` |
| **Entry point** | `run(operator_path) -> RuleResult` |
| **Scanned files** | `.go` files in the opendatahub-operator repo |
| **External deps** | `git` (for cloning the operator repo) |

### What it does

Parses the opendatahub-operator source code to build the authoritative list of `RELATED_IMAGE_*` environment variables. This manifest is the source of truth for what images must be mirrorable in disconnected environments. The rule itself produces only informational findings — its output (`manifest_env_vars`) is consumed by `image-manifest-complete` and `params-env-wiring` for cross-referencing.

### Scanning scope

The scan is performed in two passes for component attribution:

**Pass 1 — Component directories** (`internal/controller/components/*/`):
Iterates each subdirectory under `components/` and scans all `.go` files (excluding test files with `_test.go`, `_int_test.go`, `_internal_test.go` suffixes). Each env var is attributed to its specific component name (the subdirectory name, e.g., `dashboard`, `kserve`, `modelmeshserving`). Subdirectories starting with `.` or named `registry` are skipped.

**Pass 2 — Entire operator repo** (all remaining `.go` files):
Uses `root.rglob("*.go")` across the entire operator repository, explicitly skipping files already under `internal/controller/components/` (to avoid double-counting) and files in skip directories (`.git`, `vendor`, `node_modules`, `__pycache__`). Any `RELATED_IMAGE_*` references found here — for example in `internal/controller/*.go`, `cmd/`, `pkg/`, or top-level Go files — are attributed to the generic component `"operator-core"`.

The two-pass design exists for component attribution: pass 1 assigns each env var to a named component (e.g., `kserve`), while pass 2 catches any definitions outside `components/` and assigns them to `operator-core`. A single pass would lose this per-component grouping.

### Detection patterns

Two regex patterns extract env var definitions, applied in priority order:

1. **`IMAGE_MAP_PATTERN`**: `"manifest-key": "RELATED_IMAGE_*"` — captures both the manifest key and the env var name, creating an `ImageEntry` with the `manifest_key` populated. When this pattern matches a line, the standalone pattern below is not applied (avoids duplicates).

2. **`RELATED_IMAGE_PATTERN`**: Standalone `"RELATED_IMAGE_*"` strings — captures env var references without a manifest key mapping. The literal string `RELATED_IMAGE_*` (with asterisk) is explicitly skipped to avoid matching glob patterns in comments or documentation.

### Additional functions

| Function | Purpose |
|----------|---------|
| `build_manifest(operator_root)` | Core function: scans operator source in two passes, returns a `Manifest` dataclass with `images` (list of `ImageEntry`), `components` (dict of component summaries), and `known_issues` |
| `parse_manifest_entries(operator_path)` | Parses `get_all_manifests.sh` to extract the mapping of component repos to their source folders and component keys (e.g., `kserve → config`, `odh-dashboard → manifests`) |
| `parse_overlay_paths_from_arch_data(arch_data, key)` | Extracts deployed overlay paths from arch-analyzer's `kustomize_components` data for a given component key |
| `parse_known_issues(operator_root)` | Parses `component-params-env.yaml` for known image issues listed under `# known_issues:` comments |
| `clone_operator(target_dir)` | Shallow-clones the operator repo (`--depth 1`) if not already present |

### Overlay path detection via arch-analyzer

The orchestrator runs [arch-analyzer](https://github.com/ugiordan/architecture-analyzer) on the operator repo to extract `kustomize_components` data from `component-architecture.json`. This provides **overlay paths** per component — which kustomize overlays the operator actually deploys (e.g. `overlays/odh`, `overlays/rhoai`). Combined with the manifest source folder (from `get_all_manifests.sh`), this allows `params-env-wiring` to scan only operator-deployed overlays, filtering out upstream overlays (e.g. `config/runtimes`, `overlays/kubeflow`) that produce false positives.

The arch-analyzer also runs on the target component repo. The resulting `component-architecture.json` is passed to rules as `arch_data` for production scope detection and overlay classification.

### Operator cloning

When `--operator-path` is not provided, the orchestrator creates a `tempfile.TemporaryDirectory(prefix="odh-operator-")` and clones into it. The repo URL (`https://github.com/opendatahub-io/opendatahub-operator.git`) is hardcoded and never user-supplied.

---

## Production Scope

| | |
|---|---|
| **File** | `rules/production_scope.py` |
| **Entry point** | `compute_production_scope(repo_root, manifest_source_folders=None, overlay_paths=None, arch_data=None, docker_contexts=None) -> Optional[ProductionScope]` |
| **External deps** | `go` (optional, for `go list`), arch-analyzer (for `original_sources` data) |

### What it does

All rules check production scope: files outside it are skipped.

### How it determines production scope

**1. arch-analyzer original_sources** (primary method):

Reads `dockerfiles[].copy_instructions[].original_sources` from arch-analyzer output. For each Dockerfile's COPY instructions, resolves the source paths into one of three cases:

- **Glob sources** (contains `**` or `${VAR}`): Normalizes variable tokens and expands using `Path.glob()`.
- **Repo root copy** (`COPY . .`): The source is the entire repo root. Uses heuristics to narrow scope:
  - Go repos → runs `go list -deps -json ./...` to extract only imported package directories.
  - JS monorepos → finds the nearest `package.json` ancestor of the Dockerfile.
  - Central config can override with explicit `docker_contexts` mappings per repo.
- **Literal paths**: Resolved directly against the repo root.

Sets `method = "arch-analyzer-original-sources"` when production dirs are found.

**2. Manifest scope** (kustomize/helm graph walking):

For each directory in `manifest_source_folders`:
- Detects `Chart.yaml` (Helm) or `kustomization.yaml` (Kustomize).
- Helm: recursively finds all `.yaml`/`.yml` files, skipping test/examples directories.
- Kustomize: walks the `resources:` graph recursively, collecting all referenced directories and their YAML files. Handles cycles via a visited set.

These files populate the `manifest_files` set.

**3. Go-embedded YAMLs**:

Scans production `.go` files for `//go:embed` directives. Resolves glob patterns and adds matched YAML files to `manifest_files`.

### Return value

Returns a `ProductionScope` with:
- `method`: `"arch-analyzer-original-sources"` or `"manifest-only"`
- `production_dirs`: set of resolved directory paths (all file types)
- `production_files`: set of individual resolved file paths
- `manifest_files`: set of resolved YAML files in the kustomize/helm graph
- `manifest_source`: comma-separated source folder names (e.g., `"config"`)
- `overlay_paths`: list of operator-deployed overlay directories

Returns `None` when no production scope can be determined, causing all rules to scan at full severity.

---

## Orchestrator Flow

**File:** `main.py`

### Rule registry

| Alias | Module | Flags |
|-------|--------|-------|
| `csv` | `rules.image_manifest_complete` | `needs_manifest` |
| `tags` | `rules.no_image_tags` | `needs_manifest` |
| `egress` | `rules.no_runtime_egress` | — |
| `python` | `rules.python_imports` | — |
| `params_env` | `rules.params_env` | `needs_manifest` |
| `manifest` | `rules.operator_manifest` | `is_manifest_rule` |

Default rules: all except `manifest`. The `manifest` rule must be explicitly selected.

### Execution sequence

```text
1. Parse CLI arguments
2. Load central config (config/config.yaml)
   └─ Validate against JSON schema (schemas/config.schema.json)
   └─ Extract: exceptions, docker_contexts, known_non_image_prefixes, params_env_filenames
3. Detect if operator manifest is needed
   └─ Check if any selected rule has needs_manifest flag
   └─ Run detect_image_pattern() or detect_params_env() on the target repo
4. Load operator manifest (if needed)
   └─ Clone operator or use --operator-path
   └─ build_manifest() → manifest_env_vars (set of RELATED_IMAGE_* strings)
5. Run arch-analyzer on both operator and component repos
   └─ Generates component-architecture.json (cached if already present)
6. Compute production scope
   └─ Parse operator's get_all_manifests.sh → manifest_source_folders
   └─ Extract overlay_paths from arch-analyzer's kustomize_components
   └─ Call compute_production_scope()
7. Run each selected rule
   └─ Pass kwargs: manifest_env_vars, production_scope, arch_data, non_image_prefixes, extra_filenames
8. Apply exceptions from central config
   └─ Downgrade matching blocker findings to info
   └─ Track hit counts per exception entry
9. Compute score
   └─ Any rule with at least one blocker finding → NOT READY
   └─ Otherwise → READY
10. Render report(s)
    └─ Markdown (via Jinja2 template or built-in renderer) and/or JSON
    └─ Write to file(s) or stdout
```

### Exit codes

- `0` — READY (no blockers across all rules)
- `1` — NOT READY (at least one blocker) or `ArchAnalyzerError`

### Cross-rule data flow

```text
                    opendatahub-operator
                           │
                    operator_manifest.py
                      (clone + parse)
                           │
                   manifest_env_vars (set[str])
                           │
        ┌──────────────────┼──────────────────┬────────────┐
        │                  │                  │            │
   image_manifest    no_image_tags.py    params_env    (other rules
    _complete.py    (stricter check --      .py        don't use it)
        │             see its rule doc)      │
        └──────────────────┴──────────────────┘
                            │
                            ▼
              production_scope ──────► ALL rules
              (from arch-analyzer)     (downgrade non-production findings)
                     │
                     ▼
                 main.py
           ┌─────────────────┐
           │ apply_exceptions │
           │ compute_score    │
           │ render_report    │
           └─────────────────┘
```

### Configuration

All configuration is managed through `config/config.yaml`. No per-repository configuration files are supported. The schema is validated against `schemas/config.schema.json`.

Key config sections:
- **`exceptions`**: Rules that downgrade specific blocker findings to info (by rule, repo, path glob, image pattern, or message pattern).
- **`docker_contexts`**: Per-repo overrides for Dockerfile COPY context resolution in production scope analysis.
- **`known_non_image_prefixes`**: String prefixes to exclude from image detection (reduces false positives from non-image references that look like image paths).
- **`params_env_filenames`**: Per-repo custom params.env filename overrides (some repos use names other than `params.env`).
