#!/usr/bin/env python3
"""Enforce digest-only image references — reject mutable tags.

Severity pipeline:

0. ``run()`` skips files outside production scope (no finding).
1. ``_emit_finding`` — params.env excluded file → info.
2. ``_emit_finding`` — non-production kustomize overlay → info.
3. ``_emit_finding`` — YAML documentation-field line → info
   (``[documentation field]``).
4. Else emit as blocker (with source/manifest/OCI message context).
5. ``_downgrade_confirmed_related_image_findings`` post-pass — remaining
   blockers → info when a confirmed ``RELATED_IMAGE_*`` covers the image
   (enclosing-block / same-line match over emitted findings).

Orchestrator path-glob exceptions apply after the rule returns.
"""

import re
from pathlib import Path

try:
    from rules.common import (
        NON_REGISTRY_DOMAINS,
        RELATED_IMAGE_PATTERN,
        SKIP_DIRS,
        Finding,
        ProductionScope,
        RuleResult,
        Severity,
        build_overlay_file_map,
        detect_image_pattern,  # noqa: F401 -- re-exported so main.py's hasattr() detection finds it
        downgrade_non_production_overlay,
        find_params_env_dirs,
        get_tracked_files,
        is_file_in_production_scope,
        production_scope_relative_dirs,
    )
except ModuleNotFoundError:
    from common import (
        NON_REGISTRY_DOMAINS,
        RELATED_IMAGE_PATTERN,
        SKIP_DIRS,
        Finding,
        ProductionScope,
        RuleResult,
        Severity,
        build_overlay_file_map,
        detect_image_pattern,  # noqa: F401 -- re-exported so main.py's hasattr() detection finds it
        downgrade_non_production_overlay,
        find_params_env_dirs,
        get_tracked_files,
        is_file_in_production_scope,
        production_scope_relative_dirs,
    )

try:
    from rules.yaml_documentation_fields import documentation_field_lines
except ModuleNotFoundError:
    from yaml_documentation_fields import documentation_field_lines

IMAGE_REF_PATTERN = re.compile(
    r"(https?://|oci://)?"
    r"((?:[\w.\-]+(?:\.[\w.\-]+)+(?::\d+)?/)?[\w.\-]+(?:/[\w.\-]+)+)"
    r"([:@][\w.\-:]+)?"
)

K8S_UNQUALIFIED_IMAGE = re.compile(
    r"""(?:^|[\s\-])image:\s*['"]?([a-zA-Z][\w.\-]+):([\w.\-]+)['"]?\s*$"""
)

YAML_EXTENSIONS = {".yaml", ".yml"}

_SOURCE_COMMENT_PREFIXES = {
    ".go": "//",
    ".ts": "//",
    ".tsx": "//",
    ".py": "#",
    ".sh": "#",
}

SOURCE_EXTENSIONS = set(_SOURCE_COMMENT_PREFIXES)

_NAME_CONTAINS = ["Dockerfile"]

_SKIP_FILENAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "package.json",
}


def is_excluded_file(filepath: Path) -> bool:
    """Files that should produce info instead of blocker findings."""
    return filepath.name == "params.env"


def is_source_code(filepath: Path) -> bool:
    """Source code files that hardcode image refs at runtime."""
    return filepath.suffix in SOURCE_EXTENSIONS


_MAX_FILE_SIZE = 512 * 1024  # 512 KB


def _emit_finding(
    findings: list[Finding],
    filepath: Path,
    relative: str,
    line: int,
    image_str: str,
    base_msg: str,
    not_excluded_suffix: str,
    production_scope: ProductionScope | None,
    overlay_file_map: dict[str, set[Path]],
    docs_lines: set[int],
) -> None:
    """Severity stages 1–4: classify a match and append its ``Finding``.

    Both ``scan_file()`` match branches (qualified images and unqualified
    k8s ``image:`` fields) use this emitter. Stage 0 and stage 5 live in
    ``run()`` — see module docstring.
    """
    # Stage 1: params.env excluded file
    if is_excluded_file(filepath):
        severity, msg = "info", f"{base_msg} File is excluded (params.env)."
    else:
        severity = "blocker"
        msg = f"{base_msg} {not_excluded_suffix}" if not_excluded_suffix else base_msg

    # Stage 2: non-production kustomize overlay
    severity, msg = downgrade_non_production_overlay(
        severity, msg, filepath, production_scope, overlay_file_map
    )
    # Stage 3: YAML documentation-field line; stage 4: remaining blocker
    if severity == "blocker" and line in docs_lines:
        severity, msg = "info", msg + " [documentation field]"
    findings.append(
        Finding(severity=severity, file=relative, line=line, image=image_str, message=msg)
    )


def scan_file(
    filepath: Path,
    root: Path,
    production_scope: ProductionScope | None = None,
    overlay_file_map: dict[str, set[Path]] | None = None,
    non_image_prefixes: list[str] | None = None,
) -> list[Finding]:
    findings = []
    if overlay_file_map is None:
        overlay_file_map = {}
    try:
        file_size = filepath.stat().st_size
        if file_size > _MAX_FILE_SIZE:
            findings.append(
                Finding(
                    severity="info",
                    file=str(filepath.relative_to(root)),
                    line=0,
                    image="",
                    message=f"Skipped large file ({file_size // 1024}KB > {_MAX_FILE_SIZE // 1024}KB limit).",
                )
            )
            return findings
        text = filepath.read_text()
        lines = text.splitlines()
    except (OSError, UnicodeDecodeError):
        return findings

    is_yaml = filepath.suffix in YAML_EXTENSIONS or filepath.name == "params.env"
    docs_lines = documentation_field_lines(text) if filepath.suffix in YAML_EXTENSIONS else set()
    found_on_line = set()

    for i, line in enumerate(lines, 1):
        if line.strip().startswith("#") or line.strip().startswith("//"):
            continue

        for match in IMAGE_REF_PATTERN.finditer(line):
            prefix = match.group(1) or ""
            repo_part = match.group(2)
            ref_part = match.group(3)

            if prefix.startswith("http"):
                continue

            is_oci = prefix == "oci://"

            if not is_oci:
                if not ref_part:
                    continue
                if "/" not in repo_part:
                    continue
                if any(len(p) <= 1 for p in repo_part.split("/")):
                    continue
                if ref_part.startswith("@sha256:"):
                    continue
                domain = repo_part.split("/")[0].split(":")[0]
                if domain in NON_REGISTRY_DOMAINS:
                    continue
                if non_image_prefixes and any(repo_part.startswith(p) for p in non_image_prefixes):
                    continue
            if is_oci:
                if ref_part and ref_part.startswith("@sha256:"):
                    continue
                image_str = f"oci://{repo_part}"
                if ref_part:
                    image_str += ref_part
                    base_msg = (
                        f"OCI URI `{image_str}` uses tag '{ref_part}' instead of digest. "
                        f"Must use @sha256: digest for disconnected mirroring."
                    )
                else:
                    base_msg = (
                        f"OCI URI `{image_str}` has no digest pin. "
                        f"Must use @sha256: digest for disconnected mirroring."
                    )
            else:
                image_str = f"{repo_part}{ref_part}"
                base_msg = (
                    f"Image `{image_str}` uses tag '{ref_part}' instead of digest. "
                    f"Tags cannot be reliably mirrored."
                )

            relative = str(filepath.relative_to(root))
            if is_oci:
                suffix = ""
            elif is_source_code(filepath):
                suffix = "Hardcoded in source code."
            else:
                suffix = "Manifest file not managed by params.env."

            found_on_line.add(i)
            _emit_finding(
                findings,
                filepath,
                relative,
                i,
                image_str,
                base_msg,
                suffix,
                production_scope,
                overlay_file_map,
                docs_lines,
            )

        if is_yaml and i not in found_on_line:
            m = K8S_UNQUALIFIED_IMAGE.search(line.strip())
            if m:
                name, tag = m.group(1), m.group(2)
                if tag.startswith("sha256"):
                    continue
                image_str = f"{name}:{tag}"
                relative = str(filepath.relative_to(root))
                base_msg = (
                    f"Unqualified image `{image_str}` in k8s manifest "
                    f"uses tag ':{tag}' instead of digest."
                )

                _emit_finding(
                    findings,
                    filepath,
                    relative,
                    i,
                    image_str,
                    base_msg,
                    "Manifest file not managed by params.env.",
                    production_scope,
                    overlay_file_map,
                    docs_lines,
                )

    return findings


_MAX_BLOCK_SPAN_LINES = 80


def _comment_prefix_for(filepath: Path) -> str:
    """Line-comment prefix for the languages in SOURCE_EXTENSIONS."""
    return _SOURCE_COMMENT_PREFIXES.get(filepath.suffix, "")


_TRIPLE_QUOTE_DELIMS = {"triple_dquote": '"""', "triple_squote": "'''"}


def _scan_line(
    raw_line: str,
    comment_prefix: str,
    entry_state: str | None,
) -> tuple[list[tuple[int, bool]], int, str | None]:
    """Scan one line for paren events and the column where a real trailing
    comment begins, tracking quote state.

    Single- and double-quoted strings are scanned per line -- state does
    not carry to the next line, so an unterminated regular quote is
    contained to that one line, the same as malformed source. Backtick
    strings (Go raw strings, TS/TSX template literals) and Python
    triple-quoted strings can span multiple lines, so their state is
    threaded across lines via entry_state / the returned exit state.

    Returns (events, comment_start, exit_state):
      - events: (column, is_open) for real parens -- not inside any
        string, and not part of a trailing comment. is_open is True for
        "(" and False for ")".
      - comment_start: column where a real comment begins, or len(raw_line)
        if none. Everything from this column on is not code.
      - exit_state: quote state to pass as entry_state for the next line
        (None, "backtick", "triple_dquote", or "triple_squote").
    """
    events: list[tuple[int, bool]] = []
    state = entry_state
    in_squote = False
    in_dquote = False
    i = 0
    n = len(raw_line)
    while i < n:
        if state is not None:
            delim = _TRIPLE_QUOTE_DELIMS.get(state)
            if delim is not None:
                if raw_line.startswith(delim, i):
                    state = None
                    i += 3
                else:
                    i += 1
            else:  # state == "backtick"
                if raw_line[i] == "`":
                    state = None
                i += 1
            continue
        if in_squote:
            if raw_line[i] == "\\":
                i += 2
                continue
            if raw_line[i] == "'":
                in_squote = False
            i += 1
            continue
        if in_dquote:
            if raw_line[i] == "\\":
                i += 2
                continue
            if raw_line[i] == '"':
                in_dquote = False
            i += 1
            continue
        if comment_prefix and raw_line.startswith(comment_prefix, i):
            return events, i, state
        if raw_line.startswith('"""', i):
            state = "triple_dquote"
            i += 3
            continue
        if raw_line.startswith("'''", i):
            state = "triple_squote"
            i += 3
            continue
        ch = raw_line[i]
        if ch == "`":
            state = "backtick"
        elif ch == "'":
            in_squote = True
        elif ch == '"':
            in_dquote = True
        elif ch == "(":
            events.append((i, True))
        elif ch == ")":
            events.append((i, False))
        i += 1
    return events, n, state


def _index_file(
    lines: list[str],
    comment_prefix: str,
) -> tuple[list[tuple[tuple[int, int], tuple[int, int]]], list[int]]:
    """Scan every line of a file once, threading quote state across lines
    (see _scan_line).

    Returns (pairs, comment_starts):
      - pairs: every completed (open_pos, close_pos) paren pair, as exact
        (line, column) positions (1-indexed line).
      - comment_starts: the comment-start column for every line (0-indexed
        list aligned with `lines`), used to strip trailing comments when
        building block text.
    """
    stack: list[tuple[int, int]] = []
    pairs: list[tuple[tuple[int, int], tuple[int, int]]] = []
    comment_starts: list[int] = []
    state: str | None = None
    for idx, raw_line in enumerate(lines, start=1):
        events, comment_start, state = _scan_line(raw_line, comment_prefix, state)
        comment_starts.append(comment_start)
        for col, is_open in events:
            if is_open:
                stack.append((idx, col))
            elif stack:
                open_pos = stack.pop()
                pairs.append((open_pos, (idx, col)))
            # an unmatched ')' (malformed/truncated source) is ignored
    return pairs, comment_starts


def _find_enclosing_paren_block(
    pairs: list[tuple[tuple[int, int], tuple[int, int]]],
    line_num: int,
    match_col: int,
) -> tuple[int, int, int, int] | None:
    """Find the innermost balanced-paren block enclosing (line_num,
    match_col), from a paren-pair index already built by _index_file().

    Returns (open_line, open_col, close_line, close_col), 1-indexed lines,
    or None when unresolved (no enclosing block, or the span exceeds
    _MAX_BLOCK_SPAN_LINES). See docs/rules-reference.md's "Manifest
    cross-reference downgrade" section for the full matching semantics and
    known limitations.
    """
    target = (line_num, match_col)
    best: tuple[tuple[int, int], tuple[int, int]] | None = None
    for open_pos, close_pos in pairs:
        if open_pos < target < close_pos and (best is None or open_pos > best[0]):
            best = (open_pos, close_pos)

    if best is None:
        return None

    (open_line, open_col), (close_line, close_col) = best
    if close_line - open_line > _MAX_BLOCK_SPAN_LINES:
        return None
    return (open_line, open_col, close_line, close_col)


def _nth_occurrence_column(line: str, needle: str, occurrence: int) -> int:
    """Column of the (0-indexed) `occurrence`-th occurrence of `needle` in
    `line`, or -1 if there is no such occurrence. Used so that multiple
    findings sharing the same image text on one line each resolve against
    their own occurrence, not all against the first one."""
    start = 0
    idx = -1
    for _ in range(occurrence + 1):
        idx = line.find(needle, start)
        if idx == -1:
            return -1
        start = idx + 1
    return idx


def _resolve_block_for_finding(
    finding: Finding,
    filepath: Path,
    lines: list[str],
    occurrence: int,
    file_index_cache: dict[Path, tuple[list[tuple[tuple[int, int], tuple[int, int]]], list[int]]],
) -> tuple[int, int, str]:
    """Resolve the (start_line, end_line, block_text) span to search for a
    confirmed RELATED_IMAGE_* var for one finding.

    For source-code files, finds the balanced-paren block enclosing the
    finding's `occurrence`-th match of its image text on its own line.
    Falls back to same-line-only when the match can't be resolved to a
    specific column (non-source file, or the image text isn't found on its
    reported line), or when no enclosing block exists.
    """
    line_content = lines[finding.line - 1]

    match_col = -1
    if is_source_code(filepath):
        match_col = _nth_occurrence_column(line_content, finding.image, occurrence)

    if match_col == -1:
        return finding.line, finding.line, line_content

    if filepath not in file_index_cache:
        file_index_cache[filepath] = _index_file(lines, _comment_prefix_for(filepath))
    pairs, comment_starts = file_index_cache[filepath]
    block = _find_enclosing_paren_block(pairs, finding.line, match_col)

    if block is None:
        return finding.line, finding.line, line_content

    open_line, open_col, close_line, close_col = block
    block_lines = []
    for ln in range(open_line, close_line + 1):
        text = lines[ln - 1][: comment_starts[ln - 1]]
        if ln == open_line:
            text = text[open_col:]
            local_close_col = close_col - open_col if close_line == open_line else None
        else:
            local_close_col = close_col if ln == close_line else None
        if local_close_col is not None:
            text = text[: local_close_col + 1]
        block_lines.append(text)
    return open_line, close_line, "\n".join(block_lines)


def _downgrade_confirmed_related_image_findings(
    result: RuleResult,
    root: Path,
    manifest_env_vars: set[str],
) -> None:
    """Severity stage 5: RELATED_IMAGE coverage on remaining blockers.

    Downgrades a blocker to info when a confirmed RELATED_IMAGE_* var covers
    the image (enclosing-block / same-line match). See
    docs/rules-reference.md's "Manifest cross-reference downgrade" section
    for matching semantics and known limitations.
    """
    blockers = [f for f in result.findings if f.severity == "blocker"]
    if not blockers:
        return

    file_lines_cache: dict[Path, list[str]] = {}
    file_index_cache: dict[
        Path, tuple[list[tuple[tuple[int, int], tuple[int, int]]], list[int]]
    ] = {}
    occurrence_counts: dict[tuple[Path, int, str], int] = {}

    for finding in blockers:
        filepath = root / finding.file
        if filepath not in file_lines_cache:
            try:
                file_lines_cache[filepath] = filepath.read_text().splitlines()
            except (OSError, UnicodeDecodeError):
                file_lines_cache[filepath] = []
        lines = file_lines_cache[filepath]

        if not (0 < finding.line <= len(lines)):
            continue

        key = (filepath, finding.line, finding.image)
        occurrence = occurrence_counts.get(key, 0)
        occurrence_counts[key] = occurrence + 1

        start, end, block_text = _resolve_block_for_finding(
            finding, filepath, lines, occurrence, file_index_cache
        )
        confirmed_vars = set(RELATED_IMAGE_PATTERN.findall(block_text)) & manifest_env_vars

        if confirmed_vars:
            finding.severity = Severity.INFO
            if start == end:
                location = "Line also references"
            else:
                location = f"Enclosing call (lines {start}-{end}) also references"
            finding.message += (
                f" {location} confirmed RELATED_IMAGE_* var(s) "
                f"{', '.join(sorted(confirmed_vars))}; image-manifest-complete "
                f"already validates this image against the operator manifest."
            )

    result.passed = not any(f.severity == "blocker" for f in result.findings)


def run(
    repo_root: str,
    manifest_env_vars: set[str] | None = None,
    production_scope=None,
    arch_data=None,
    non_image_prefixes: list[str] | None = None,
    **_kwargs,
) -> RuleResult:
    root = Path(repo_root)
    result = RuleResult(rule="no-image-tags")
    skip_dirs = SKIP_DIRS
    extensions = {".go", ".py", ".yaml", ".yml", ".json", ".toml"}
    params_env_dirs = find_params_env_dirs(root)
    params_env_prefixes = tuple(str(d) + "/" for d in params_env_dirs)
    tracked = get_tracked_files(root)
    overlay_file_map = build_overlay_file_map(arch_data, root)

    result.scan_filters = {
        "globs": ["**/*"],
        "extensions": sorted(extensions),
        "name_contains": _NAME_CONTAINS,
        "skip_dirs": sorted(skip_dirs),
        "skip_filenames": sorted(_SKIP_FILENAMES),
        "tracked_files_only": tracked is not None,
    }
    prod_dirs = production_scope_relative_dirs(production_scope, root)
    if prod_dirs is not None:
        result.scan_filters["production_scope_dirs"] = prod_dirs
    if params_env_dirs:
        result.scan_filters["params_env_dirs_excluded"] = sorted(
            str(d.relative_to(root.resolve())) + "/"
            for d in params_env_dirs
            if d.is_relative_to(root.resolve())
        )

    for filepath in root.rglob("*"):
        if filepath.name in _SKIP_FILENAMES:
            continue
        if filepath.suffix not in extensions and not any(
            s in filepath.name for s in _NAME_CONTAINS
        ):
            continue
        if any(d in filepath.parts for d in skip_dirs):
            continue
        resolved = filepath.resolve()
        if tracked is not None and resolved not in tracked:
            continue
        if params_env_prefixes and str(resolved).startswith(params_env_prefixes):
            continue
        # Stage 0: outside production scope → skip
        if is_file_in_production_scope(filepath, production_scope) is False:
            continue

        result.files_checked.append(str(filepath.relative_to(root)))
        for finding in scan_file(
            filepath,
            root,
            production_scope=production_scope,
            overlay_file_map=overlay_file_map,
            non_image_prefixes=non_image_prefixes,
        ):
            result.findings.append(finding)
            if finding.severity == "blocker":
                result.passed = False

    # Stage 5: RELATED_IMAGE coverage on remaining blockers
    if manifest_env_vars is not None:
        _downgrade_confirmed_related_image_findings(result, root, manifest_env_vars)

    return result


if __name__ == "__main__":
    import json
    import sys

    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    r = run(repo)
    print(
        json.dumps(
            {
                "rule": r.rule,
                "passed": r.passed,
                "findings": [
                    {
                        "severity": f.severity,
                        "file": f.file,
                        "line": f.line,
                        "image": f.image,
                        "message": f.message,
                    }
                    for f in r.findings
                ],
            },
            indent=2,
        )
    )
