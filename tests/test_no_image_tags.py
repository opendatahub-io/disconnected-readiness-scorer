"""Tests for rules/no_image_tags.py"""

from pathlib import Path

from rules.common import Finding, ProductionScope, RuleResult
from rules.no_image_tags import (
    _comment_prefix_for,
    _downgrade_confirmed_related_image_findings,
    _find_enclosing_paren_block,
    _index_file,
    _nth_occurrence_column,
    _resolve_block_for_finding,
    _scan_line,
    is_excluded_file,
    is_source_code,
    run,
    scan_file,
)


class TestIsExcludedFile:
    def test_params_env(self):
        assert is_excluded_file(Path("manifests/params.env")) is True

    def test_regular_file(self):
        assert is_excluded_file(Path("pkg/server.go")) is False


class TestIsSourceCode:
    def test_go_file(self):
        assert is_source_code(Path("pkg/main.go")) is True

    def test_python_file(self):
        assert is_source_code(Path("src/app.py")) is True

    def test_shell_file(self):
        assert is_source_code(Path("scripts/run.sh")) is True

    def test_yaml_file(self):
        assert is_source_code(Path("config/deploy.yaml")) is False

    def test_json_file(self):
        assert is_source_code(Path("config/settings.json")) is False


class TestCommentPrefixFor:
    def test_go_uses_slash_slash(self):
        assert _comment_prefix_for(Path("pkg/main.go")) == "//"

    def test_ts_uses_slash_slash(self):
        assert _comment_prefix_for(Path("src/app.ts")) == "//"

    def test_tsx_uses_slash_slash(self):
        assert _comment_prefix_for(Path("src/App.tsx")) == "//"

    def test_python_uses_hash(self):
        assert _comment_prefix_for(Path("src/app.py")) == "#"

    def test_shell_uses_hash(self):
        assert _comment_prefix_for(Path("scripts/run.sh")) == "#"

    def test_unknown_extension_returns_empty(self):
        assert _comment_prefix_for(Path("config/deploy.yaml")) == ""


class TestScanFile:
    def test_digest_ref_skipped(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("image: quay.io/org/img@sha256:" + "a" * 64)
        assert scan_file(f, tmp_path) == []

    def test_tag_ref_in_source_is_blocker(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        f = pkg / "main.go"
        f.write_text("image: quay.io/org/img:latest")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "blocker"
        assert ":latest" in findings[0].image

    def test_tag_ref_in_manifest_is_blocker(self, tmp_path):
        manifests = tmp_path / "manifests"
        manifests.mkdir()
        f = manifests / "deploy.yaml"
        f.write_text("image: quay.io/org/img:v1.0")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "blocker"

    def test_tag_ref_in_test_dir_is_blocker(self, tmp_path):
        test_dir = tmp_path / "test"
        test_dir.mkdir()
        f = test_dir / "helper.go"
        f.write_text("image: quay.io/org/img:v1.0")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "blocker"

    def test_tag_ref_in_test_go_file_is_blocker(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        f = pkg / "handler_test.go"
        f.write_text("image: quay.io/org/img:v1.0")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "blocker"

    def test_tag_ref_in_python_source_is_blocker(self, tmp_path):
        f = tmp_path / "app.py"
        f.write_text('image = "quay.io/org/img:latest"')
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "blocker"

    def test_hash_comment_skipped(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("# image: quay.io/org/img:v1")
        assert scan_file(f, tmp_path) == []

    def test_slash_comment_skipped(self, tmp_path):
        f = tmp_path / "main.go"
        f.write_text("// image: quay.io/org/img:v1")
        assert scan_file(f, tmp_path) == []

    def test_https_url_skipped(self, tmp_path):
        f = tmp_path / "go.mod"
        f.write_text("require https://github.com/kubernetes/api:v0.28.0")
        assert scan_file(f, tmp_path) == []

    def test_http_url_skipped(self, tmp_path):
        f = tmp_path / "main.go"
        f.write_text('url := "http://registry.example.com/org/img:v1"')
        assert scan_file(f, tmp_path) == []

    def test_non_registry_domain_skips_go_module_import(self, tmp_path):
        f = tmp_path / "conversion.go"
        f.write_text('import "sigs.k8s.io/gateway-api-inference-extension@v1.4.0"\n')
        assert scan_file(f, tmp_path) == []

    def test_image_ref_not_url_still_detected(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("image: quay.io/org/img:v1")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].image == "quay.io/org/img:v1"

    def test_unreadable_file(self, tmp_path):
        f = tmp_path / "binary.go"
        f.write_bytes(b"\x80\x81\x82" * 100)
        assert scan_file(f, tmp_path) == []

    def test_finding_has_correct_line_number(self, tmp_path):
        f = tmp_path / "main.go"
        f.write_text("line1\nline2\nimage: quay.io/org/img:v1\nline4")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].line == 3

    def test_finding_has_relative_path(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        f = pkg / "client.go"
        f.write_text("image: quay.io/org/img:latest")
        findings = scan_file(f, tmp_path)
        assert findings[0].file == "pkg/client.go"


class TestRun:
    def test_empty_repo(self, tmp_path):
        result = run(str(tmp_path))
        assert result.passed is True
        assert result.findings == []
        assert result.rule == "no-image-tags"

    def test_skips_pnpm_workspace_configuration(self, tmp_path):
        workspace = tmp_path / "pnpm-workspace.yaml"
        workspace.write_text(
            "packageExtensions:\n"
            "  '@perses-dev/loki-plugin@0.6.0-rc.2':\n"
            "    peerDependencies:\n"
            "      '@mui/material': '^6.1.10'\n"
        )

        result = run(str(tmp_path))

        assert result.passed is True
        assert result.findings == []
        assert "pnpm-workspace.yaml" in result.scan_filters["skip_filenames"]

    def test_skips_git_dir(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        f = git_dir / "config"
        f.write_text("image: quay.io/org/img:latest")
        result = run(str(tmp_path))
        assert result.findings == []

    def test_skips_vendor_dir(self, tmp_path):
        vendor = tmp_path / "vendor"
        vendor.mkdir()
        f = vendor / "dep.go"
        f.write_text("image: quay.io/org/img:latest")
        result = run(str(tmp_path))
        assert result.findings == []

    def test_skips_non_matching_extension(self, tmp_path):
        f = tmp_path / "readme.txt"
        f.write_text("image: quay.io/org/img:latest")
        result = run(str(tmp_path))
        assert result.findings == []

    def test_dockerfile_scanned(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM quay.io/org/base:latest")
        result = run(str(tmp_path))
        assert any(f.file == "Dockerfile" for f in result.findings)

    def test_manifest_tag_sets_passed_false(self, tmp_path):
        manifests = tmp_path / "manifests"
        manifests.mkdir()
        f = manifests / "deploy.yaml"
        f.write_text("image: quay.io/org/img:v1.0")
        result = run(str(tmp_path))
        assert result.passed is False
        assert result.findings[0].severity == "blocker"

    def test_source_code_tag_sets_passed_false(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        f = pkg / "main.go"
        f.write_text("image: quay.io/org/img:latest")
        result = run(str(tmp_path))
        assert result.passed is False
        assert any(f.severity == "blocker" for f in result.findings)

    def test_mixed_findings(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        test_dir = tmp_path / "test"
        test_dir.mkdir()

        (pkg / "main.go").write_text("image: quay.io/org/img@sha256:" + "a" * 64)
        (test_dir / "helper.go").write_text("image: quay.io/org/img:v1")

        result = run(str(tmp_path))
        assert result.passed is False
        assert any(f.severity == "blocker" for f in result.findings)

    def test_docs_only_findings_leave_passed_true(self, tmp_path):
        f = tmp_path / "crd.yaml"
        f.write_text("description: |-\n  Example: ghcr.io/org/tool:latest\n")
        result = run(str(tmp_path))
        assert result.passed is True
        assert len(result.findings) >= 1
        assert all(finding.severity == "info" for finding in result.findings)
        assert any("[documentation field]" in finding.message for finding in result.findings)


class TestProductionScope:
    def test_out_of_scope_go_file_downgraded(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        f = pkg / "images.go"
        f.write_text('var img = "quay.io/org/app:v1.0"')
        cmd = tmp_path / "cmd"
        cmd.mkdir()
        other = cmd / "main.go"
        other.write_text("package main\n")
        scope = ProductionScope(
            production_dirs={cmd.resolve()},
            method="go-import-graph",
        )
        result = run(str(tmp_path), production_scope=scope)
        assert result.passed is True
        assert len(result.findings) == 0

    def test_in_scope_go_file_stays_blocker(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        f = pkg / "images.go"
        f.write_text('var img = "quay.io/org/app:v1.0"')
        scope = ProductionScope(
            production_dirs={f.parent.resolve()},
            method="go-import-graph",
        )
        result = run(str(tmp_path), production_scope=scope)
        assert result.passed is False
        assert result.findings[0].severity == "blocker"

    def test_non_go_file_unaffected(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("image: quay.io/org/app:v1.0")
        scope = ProductionScope(method="go-import-graph")
        result = run(str(tmp_path), production_scope=scope)
        assert result.findings[0].severity == "blocker"


class TestOciUri:
    def test_oci_uri_without_digest_is_blocker(self, tmp_path):
        f = tmp_path / "constants.py"
        f.write_text('storage_uri="oci://quay.io/org/model-name"')
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "blocker"
        assert findings[0].image == "oci://quay.io/org/model-name"
        assert "no digest pin" in findings[0].message

    def test_oci_uri_with_digest_skipped(self, tmp_path):
        f = tmp_path / "constants.py"
        f.write_text('uri="oci://quay.io/org/model@sha256:abcdef1234567890"')
        findings = scan_file(f, tmp_path)
        assert findings == []

    def test_oci_uri_deep_path(self, tmp_path):
        f = tmp_path / "conftest.py"
        f.write_text('uri="oci://quay.io/trustyai/detectors/granite-guardian-hap"')
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert "oci://quay.io/trustyai/detectors/granite-guardian-hap" in findings[0].image

    def test_oci_uri_with_tag_is_blocker(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("storage_uri: oci://registry.example.com/org/model:v1.0")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "blocker"
        assert "tag" in findings[0].message

    def test_oci_uri_in_params_env_is_info(self, tmp_path):
        f = tmp_path / "params.env"
        f.write_text("MODEL=oci://quay.io/org/model-name")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "info"

    def test_oci_uri_out_of_production_scope_skipped(self, tmp_path):
        test_dir = tmp_path / "tests"
        test_dir.mkdir()
        f = test_dir / "test_utils.go"
        f.write_text('uri := "oci://quay.io/org/test-model"')
        cmd = tmp_path / "cmd"
        cmd.mkdir()
        other = cmd / "main.go"
        other.write_text("package main\n")
        scope = ProductionScope(
            production_dirs={cmd.resolve()},
            method="go-import-graph",
        )
        result = run(str(tmp_path), production_scope=scope)
        oci_findings = [f for f in result.findings if "oci://" in f.image]
        assert len(oci_findings) == 0

    def test_plain_path_not_matched(self, tmp_path):
        f = tmp_path / "main.go"
        f.write_text('path := "cmd/manager/main.go"')
        findings = scan_file(f, tmp_path)
        assert findings == []

    def test_oci_uri_sets_passed_false(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("storage_uri: oci://quay.io/org/model-name")
        result = run(str(tmp_path))
        assert result.passed is False


class TestNpmPackagesNotDetected:
    def test_package_json_skipped(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text('{"dependencies": {"vscode/l10n-dev": "0.0.35"}}')
        result = run(str(tmp_path))
        assert result.findings == []


class TestK8sUnqualifiedImage:
    def test_unqualified_image_in_yaml_is_blocker(self, tmp_path):
        f = tmp_path / "job.yaml"
        f.write_text("      containers:\n      - name: migrate\n        image: origin-cli:latest")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "blocker"
        assert findings[0].image == "origin-cli:latest"
        assert "Unqualified image" in findings[0].message

    def test_unqualified_nginx_tag_in_yaml(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("spec:\n  containers:\n  - image: nginx:1.25")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "blocker"
        assert findings[0].image == "nginx:1.25"

    def test_unqualified_image_double_quoted(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text('        image: "origin-cli:latest"')
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].image == "origin-cli:latest"

    def test_unqualified_image_single_quoted(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("        image: 'nginx:1.25'")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].image == "nginx:1.25"

    def test_unqualified_image_not_matched_in_go(self, tmp_path):
        f = tmp_path / "main.go"
        f.write_text("image: origin-cli:latest")
        findings = scan_file(f, tmp_path)
        assert findings == []

    def test_qualified_image_no_duplicate(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("        image: quay.io/org/img:v1")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert "Unqualified" not in findings[0].message

    def test_unqualified_without_image_prefix_not_matched(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("name: origin-cli:latest")
        findings = scan_file(f, tmp_path)
        assert findings == []

    def test_unqualified_in_params_env_is_info(self, tmp_path):
        f = tmp_path / "params.env"
        f.write_text("image: origin-cli:latest")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "info"

    def test_unqualified_sets_passed_false(self, tmp_path):
        f = tmp_path / "job.yaml"
        f.write_text("        image: origin-cli:latest")
        result = run(str(tmp_path))
        assert result.passed is False


class TestScanLine:
    def test_simple_parens(self):
        events, comment_start, state = _scan_line("foo(a, b)", "//", None)
        assert events == [(3, True), (8, False)]
        assert comment_start == len("foo(a, b)")
        assert state is None

    def test_paren_inside_double_quoted_string_ignored(self):
        events, _, state = _scan_line('foo("(", b)', "//", None)
        assert events == [(3, True), (10, False)]
        assert state is None

    def test_paren_inside_single_quoted_string_ignored(self):
        events, _, state = _scan_line("foo('(', b)", "//", None)
        assert events == [(3, True), (10, False)]
        assert state is None

    def test_escaped_quote_does_not_close_string_early(self):
        # the \" is an escaped quote inside the string, not the closing quote
        line = 'foo("a\\"(", b)'
        events, _, state = _scan_line(line, "//", None)
        assert events == [(3, True), (len(line) - 1, False)]
        assert state is None

    def test_trailing_comment_stripped(self):
        line = "foo(a) // bar("
        events, comment_start, state = _scan_line(line, "//", None)
        assert events == [(3, True), (5, False)]
        assert comment_start == line.index("//")
        assert state is None

    def test_comment_prefix_inside_string_not_treated_as_comment(self):
        line = 'x := "oci://reg/img" + foo()'
        events, comment_start, state = _scan_line(line, "//", None)
        assert events == [(line.index("foo(") + 3, True), (line.index("foo(") + 4, False)]
        assert comment_start == len(line)
        assert state is None

    def test_no_parens(self):
        events, _, state = _scan_line('x := "no parens here"', "//", None)
        assert events == []
        assert state is None

    def test_hash_comment_prefix(self):
        line = "foo(a) # bar("
        events, comment_start, _ = _scan_line(line, "#", None)
        assert events == [(3, True), (5, False)]
        assert comment_start == line.index("#")

    def test_backtick_string_on_one_line_hides_its_paren(self):
        # regression: a Go raw string / TS template literal opening and
        # closing on the same line must not leak its paren as real code.
        events, _, state = _scan_line("var help = `usage: foo(bar`", "//", None)
        assert events == []
        assert state is None

    def test_unterminated_backtick_carries_state_to_next_line(self):
        events, _, state = _scan_line("x := `abc", "//", None)
        assert events == []
        assert state == "backtick"

    def test_backtick_state_from_previous_line_hides_paren_until_closed(self):
        # entering already inside a backtick string (state carried over from
        # a previous line): everything up to the closing backtick is string
        # content, not code.
        events, _, state = _scan_line("some(text) more`", "//", "backtick")
        assert events == []
        assert state is None

    def test_code_resumes_after_backtick_closes_mid_line(self):
        line = "closing` + real(x)"
        events, _, state = _scan_line(line, "//", "backtick")
        assert events == [(line.index("real(") + 4, True), (len(line) - 1, False)]
        assert state is None

    def test_triple_double_quote_opens_and_carries_state(self):
        events, _, state = _scan_line('doc := """', "//", None)
        assert events == []
        assert state == "triple_dquote"

    def test_triple_double_quote_hides_paren_mid_string(self):
        events, _, state = _scan_line("    note (see appendix", "//", "triple_dquote")
        assert events == []
        assert state == "triple_dquote"

    def test_triple_double_quote_closes_and_resumes_code(self):
        line = '    """ + real(x)'
        events, _, state = _scan_line(line, "//", "triple_dquote")
        assert events == [(line.index("real(") + 4, True), (len(line) - 1, False)]
        assert state is None

    def test_triple_single_quote_spans_lines(self):
        _, _, state1 = _scan_line("doc := '''", "//", None)
        assert state1 == "triple_squote"
        events2, _, state2 = _scan_line("    (unbalanced", "//", state1)
        assert events2 == []
        assert state2 == "triple_squote"
        events3, _, state3 = _scan_line("    '''", "//", state2)
        assert events3 == []
        assert state3 is None

    def test_comment_prefix_ignored_while_inside_carried_backtick_state(self):
        # a "//"-looking sequence inside a still-open backtick string is
        # string content, not a real comment.
        line = "some // text` real(x)"
        events, _, state = _scan_line(line, "//", "backtick")
        assert state is None
        assert events == [(line.index("real(") + 4, True), (len(line) - 1, False)]


class TestIndexFile:
    def test_simple_file_produces_one_pair(self):
        lines = ["foo(a, b)"]
        pairs, comment_starts = _index_file(lines, "//")
        assert pairs == [((1, 3), (1, 8))]
        assert comment_starts == [len(lines[0])]

    def test_nested_calls_produce_nested_pairs(self):
        lines = ["outer(inner(x))"]
        pairs, _ = _index_file(lines, "//")
        assert len(pairs) == 2
        (outer_open, outer_close), (inner_open, inner_close) = sorted(pairs, key=lambda p: p[0][1])
        assert outer_open < inner_open < inner_close < outer_close

    def test_backtick_spanning_multiple_lines_hides_inner_paren(self):
        # regression: a Go raw string opened on one line and closed on a
        # later line must hide any paren inside it from the index entirely.
        lines = [
            "x := `line one (",
            "line two)",
            "line three`",
            "real(y)",
        ]
        pairs, _ = _index_file(lines, "//")
        assert pairs == [((4, lines[3].index("(")), (4, lines[3].index(")")))]

    def test_triple_quote_spanning_multiple_lines_hides_inner_paren(self):
        # regression: a Python triple-quoted string spanning lines must
        # hide a paren in its prose from the index -- this is the exact
        # mechanism that let a bogus, unrelated block wrap an image.
        lines = [
            "doc = (",
            '    """',
            "    note (see appendix",
            '    """',
            ")",
            "real(y)",
        ]
        pairs, _ = _index_file(lines, "//")
        outer_open = (1, lines[0].index("("))
        outer_close = (5, lines[4].index(")"))
        assert (outer_open, outer_close) in pairs
        # the "(" inside the triple-quoted prose on line 3 must never
        # appear as an open position in any pair -- it is string content.
        assert not any(open_pos[0] == 3 for open_pos, _ in pairs)
        real_open = (6, lines[5].index("("))
        real_close = (6, lines[5].index(")"))
        assert (real_open, real_close) in pairs

    def test_comment_starts_per_line(self):
        lines = ["foo() // bar", "baz()"]
        _, comment_starts = _index_file(lines, "//")
        assert comment_starts == [lines[0].index("//"), len(lines[1])]


class TestFindEnclosingParenBlock:
    @staticmethod
    def _pairs(lines, comment_prefix="//"):
        pairs, _ = _index_file(lines, comment_prefix)
        return pairs

    def test_motivating_multiline_call(self):
        lines = [
            'templateData["KubeRBACProxyImage"] = getEnvOrDefault(',
            '    "RELATED_IMAGE_ODH_KUBE_RBAC_PROXY_IMAGE",',
            '    "quay.io/brancz/kube-rbac-proxy:v0.20.0",',
            ")",
        ]
        col = lines[2].find("quay.io/brancz/kube-rbac-proxy:v0.20.0")
        pairs = self._pairs(lines)
        result = _find_enclosing_paren_block(pairs, 3, col)
        assert result == (1, lines[0].index("("), 4, lines[3].index(")"))

    def test_reversed_argument_order_call_opens_on_image_line(self):
        lines = [
            'templateData["X"] = getEnvOrDefault("quay.io/brancz/kube-rbac-proxy:v0.20.0",',
            '    "RELATED_IMAGE_ODH_KUBE_RBAC_PROXY_IMAGE",',
            ")",
        ]
        col = lines[0].find("quay.io/brancz/kube-rbac-proxy:v0.20.0")
        pairs = self._pairs(lines)
        result = _find_enclosing_paren_block(pairs, 1, col)
        assert result == (1, lines[0].index("("), 3, lines[2].index(")"))

    def test_nested_call_inner_wins(self):
        # unlike a line-only return value, columns let this assertion prove
        # the INNER (getEnvOrDefault) pair was selected, not the outer one.
        lines = [
            "result := outer(unrelated(x, y), getEnvOrDefault(",
            '    "RELATED_IMAGE_X",',
            '    "registry/img:tag",',
            "))",
        ]
        col = lines[2].find("registry/img:tag")
        pairs = self._pairs(lines)
        result = _find_enclosing_paren_block(pairs, 3, col)
        inner_open_col = lines[0].rindex("(")  # getEnvOrDefault's own '('
        assert result == (1, inner_open_col, 4, 0)

    def test_same_line_self_closed_subcall_excluded(self):
        lines = [
            'templateData["Y"] = getEnvOrDefault(',
            '    someHelper(cfg, "unrelated:tag"),',
            '    "registry/mine:v2",',
            ")",
        ]
        col = lines[2].find("registry/mine:v2")
        pairs = self._pairs(lines)
        result = _find_enclosing_paren_block(pairs, 3, col)
        assert result == (1, lines[0].index("("), 4, lines[3].index(")"))

    def test_no_enclosing_call_returns_none(self):
        lines = ['var image = "registry/img:tag"']
        col = lines[0].find("registry/img:tag")
        pairs = self._pairs(lines)
        assert _find_enclosing_paren_block(pairs, 1, col) is None

    def test_safety_cap_falls_back_to_none(self):
        # a legitimately balanced call spanning far more than
        # _MAX_BLOCK_SPAN_LINES lines is still treated as unresolved --
        # the cap is a blunt safety valve, not a correctness oracle.
        lines = ["getEnvOrDefault("]
        for i in range(100):
            lines.append(f'    "arg{i}",')
        lines.append('    "registry/img:tag",')
        lines.append(")")
        target_line = len(lines) - 1
        col = lines[target_line - 1].find("registry/img:tag")
        pairs = self._pairs(lines)
        assert _find_enclosing_paren_block(pairs, target_line, col) is None

    def test_unmatched_closing_paren_ignored(self):
        lines = [")", 'var image = "registry/img:tag"']
        col = lines[1].find("registry/img:tag")
        pairs = self._pairs(lines)
        assert _find_enclosing_paren_block(pairs, 2, col) is None


class TestNthOccurrenceColumn:
    def test_first_occurrence(self):
        assert _nth_occurrence_column("a(1) a(1)", "a(1)", 0) == 0

    def test_second_occurrence(self):
        line = "a(1) a(1)"
        assert _nth_occurrence_column(line, "a(1)", 1) == line.index("a(1)", 1)

    def test_not_found_returns_minus_one(self):
        assert _nth_occurrence_column("nothing here", "missing", 0) == -1

    def test_occurrence_beyond_available_matches_returns_minus_one(self):
        assert _nth_occurrence_column("only one match", "match", 1) == -1


class TestManifestEnvVarsDowngrade:
    """Tests for the RELATED_IMAGE_* manifest cross-reference downgrade."""

    def test_multiline_call_downgrades_to_info(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.go").write_text(
            'templateData["X"] = getEnvOrDefault(\n'
            '    "RELATED_IMAGE_ODH_KUBE_RBAC_PROXY_IMAGE",\n'
            '    "quay.io/brancz/kube-rbac-proxy:v0.20.0",\n'
            ")\n"
        )
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_ODH_KUBE_RBAC_PROXY_IMAGE"})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "info"
        assert result.passed is True
        assert "Enclosing call (lines 1-4)" in result.findings[0].message
        assert "RELATED_IMAGE_ODH_KUBE_RBAC_PROXY_IMAGE" in result.findings[0].message

    def test_reversed_argument_order_downgrades_to_info(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.go").write_text(
            'templateData["X"] = getEnvOrDefault("quay.io/brancz/kube-rbac-proxy:v0.20.0",\n'
            '    "RELATED_IMAGE_ODH_KUBE_RBAC_PROXY_IMAGE",\n'
            ")\n"
        )
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_ODH_KUBE_RBAC_PROXY_IMAGE"})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "info"
        assert result.passed is True

    def test_cross_file_var_does_not_downgrade(self, tmp_path):
        """Regression: a var in a sibling file must NOT count as coverage."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "envvars.go").write_text('os.Getenv("RELATED_IMAGE_FOO")')
        (pkg / "defaults.go").write_text('var img = "quay.io/org/img:v1"')
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_FOO"})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "blocker"
        assert result.passed is False

    def test_unrelated_var_elsewhere_in_same_file_does_not_downgrade(self, tmp_path):
        """Regression: an unrelated var in a different statement in the SAME
        file must NOT count as coverage -- only the same enclosing call."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.go").write_text(
            'os.Getenv("RELATED_IMAGE_BAR")\nvar img = "quay.io/org/img:v1"\n'
        )
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_BAR"})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "blocker"
        assert result.passed is False

    def test_yaml_same_line_only_var_on_different_line_stays_blocker(self, tmp_path):
        """Non-source files have no call-expression concept -- only a
        same-line match can confirm coverage, never a different line."""
        f = tmp_path / "deploy.yaml"
        f.write_text("# RELATED_IMAGE_FOO\nimage: quay.io/org/img:v1\n")
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_FOO"})
        blockers = [x for x in result.findings if x.severity == "blocker"]
        assert len(blockers) == 1

    def test_yaml_same_line_var_downgrades(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("image: quay.io/org/img:v1 # RELATED_IMAGE_FOO\n")
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_FOO"})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "info"

    def test_no_manifest_env_vars_unaffected(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.go").write_text(
            'templateData["X"] = getEnvOrDefault(\n'
            '    "RELATED_IMAGE_ODH_KUBE_RBAC_PROXY_IMAGE",\n'
            '    "quay.io/brancz/kube-rbac-proxy:v0.20.0",\n'
            ")\n"
        )
        result = run(str(tmp_path))
        assert len(result.findings) == 1
        assert result.findings[0].severity == "blocker"

    def test_var_in_block_but_not_confirmed_stays_blocker(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.go").write_text(
            'templateData["X"] = getEnvOrDefault(\n'
            '    "RELATED_IMAGE_NOT_IN_MANIFEST",\n'
            '    "quay.io/brancz/kube-rbac-proxy:v0.20.0",\n'
            ")\n"
        )
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_SOMETHING_ELSE"})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "blocker"

    def test_two_independent_calls_each_downgrade_from_own_block_only(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.go").write_text(
            "func a() {\n"
            "  x := getEnvOrDefault(\n"
            '    "RELATED_IMAGE_A",\n'
            '    "registry.io/org/image-a:v1",\n'
            "  )\n"
            "}\n"
            "func b() {\n"
            "  y := getEnvOrDefault(\n"
            '    "RELATED_IMAGE_B",\n'
            '    "registry.io/org/image-b:v1",\n'
            "  )\n"
            "}\n"
        )
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_A", "RELATED_IMAGE_B"})
        assert len(result.findings) == 2
        assert all(f.severity == "info" for f in result.findings)

    def test_no_blockers_skips_downgrade_pass(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("image: quay.io/org/img@sha256:" + "a" * 64)
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_FOO"})
        assert result.findings == []
        assert result.passed is True

    def test_no_related_image_var_anywhere_stays_blocker(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        f = pkg / "main.go"
        f.write_text("image: quay.io/org/img:latest")
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_FOO"})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "blocker"

    def test_var_after_closing_paren_on_same_line_does_not_confirm(self, tmp_path):
        """Regression: a var textually after the block's closing paren, in
        a separate expression on the same line, must NOT count as coverage
        -- block_text must be built from the exact paren-delimited span,
        not the entire boundary lines."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.go").write_text(
            "x := getEnvOrDefault(\n"
            '    "irrelevant",\n'
            '    "registry/img:tag",\n'
            ') + os.Getenv("RELATED_IMAGE_UNRELATED")\n'
        )
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_UNRELATED"})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "blocker"

    def test_comment_inside_block_does_not_confirm(self, tmp_path):
        """Regression: a RELATED_IMAGE_* var mentioned only in a comment
        inside the enclosing block must NOT count as coverage."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.go").write_text(
            "x := getEnvOrDefault(\n"
            "    // see RELATED_IMAGE_FOO for background\n"
            '    "registry/img:tag",\n'
            ")\n"
        )
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_FOO"})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "blocker"

    def test_duplicate_image_text_on_one_line_resolves_each_finding_independently(self, tmp_path):
        """Regression: two independent calls sharing the exact same image
        text on one line must each resolve against their own block, not
        both against the first occurrence (str.find always returns the
        first match)."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.go").write_text(
            'a("RELATED_IMAGE_A", "registry/org/img:tag"); '
            'b("RELATED_IMAGE_B", "registry/org/img:tag")\n'
        )
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_A"})
        assert len(result.findings) == 2
        assert sorted(f.severity for f in result.findings) == ["blocker", "info"]

    def test_backtick_string_does_not_corrupt_downgrade(self, tmp_path):
        """Regression: a Go raw string containing an unbalanced paren must
        not desynchronize block detection for unrelated code later in the
        file."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.go").write_text(
            "var help = `usage: foo(bar`\n"
            'os.Getenv("RELATED_IMAGE_UNRELATED")\n'
            'var img = "registry.io/org/other:v9"\n'
            ")\n"
        )
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_UNRELATED"})
        blockers = [f for f in result.findings if f.severity == "blocker"]
        assert len(blockers) == 1
        assert blockers[0].image == "registry.io/org/other:v9"
        assert result.passed is False

    def test_go_backtick_with_embedded_paren_does_not_corrupt_downgrade(self, tmp_path):
        """Regression: a Go raw string (e.g. embedded SQL) containing an
        unbalanced paren, both delimiting backticks on the same line, must
        not corrupt block detection for a later, unrelated image."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.go").write_text(
            "x := getEnvOrDefault(\n"
            '    "RELATED_IMAGE_FOO",\n'
            "    q := `SELECT * FROM t WHERE (a = 1`\n"
            ")\n"
            'var img = "registry/org/other-image:v1"\n'
            ")\n"
        )
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_FOO"})
        blockers = [f for f in result.findings if f.severity == "blocker"]
        assert len(blockers) == 1
        assert blockers[0].image == "registry/org/other-image:v1"

    def test_multiline_triple_quote_string_does_not_corrupt_downgrade(self, tmp_path):
        """Regression: a Python triple-quoted string spanning lines, with
        an unbalanced paren in its prose, must not let a later, unrelated
        closing paren steal the outer call's true closing paren and create
        a bogus block wrapping an unrelated image."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "helper.py").write_text(
            "x = get_env_or_default(\n"
            '    "RELATED_IMAGE_FOO",\n'
            '    doc="""\n'
            "    note (see appendix\n"
            '    """\n'
            ")\n"
            'img = "registry/org/other-image:v1"\n'
            ")\n"
        )
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_FOO"})
        blockers = [f for f in result.findings if f.severity == "blocker"]
        assert len(blockers) == 1
        assert blockers[0].image == "registry/org/other-image:v1"

    def test_python_multiline_call_downgrades_to_info(self, tmp_path):
        """Coverage gap: every prior downgrade test through run() used a
        .go file. .py is the only other extension the downgrade path
        actually reaches (see is_source_code() / run()'s scan filter)."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.py").write_text(
            'img = get_env_or_default(\n    "RELATED_IMAGE_FOO",\n    "quay.io/org/img:v1",\n)\n'
        )
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_FOO"})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "info"
        assert result.passed is True

    def test_python_trailing_hash_comment_does_not_confirm(self, tmp_path):
        """Coverage gap: the "#" comment-prefix branch for .py files was
        never exercised through run() -- only "//" (.go) was."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "defaults.py").write_text(
            "img = get_env_or_default(\n"
            "    # see RELATED_IMAGE_FOO for background\n"
            '    "quay.io/org/img:v1",\n'
            ")\n"
        )
        result = run(str(tmp_path), manifest_env_vars={"RELATED_IMAGE_FOO"})
        assert len(result.findings) == 1
        assert result.findings[0].severity == "blocker"


class TestResolveBlockForFinding:
    """Direct unit tests for the match_col/block resolution extracted out
    of _downgrade_confirmed_related_image_findings, independent of
    severity mutation and message formatting."""

    def test_multiline_call_resolves_full_block(self):
        lines = [
            "x := getEnvOrDefault(",
            '    "RELATED_IMAGE_FOO",',
            '    "registry/img:tag",',
            ")",
        ]
        finding = Finding(
            severity="blocker", file="f.go", line=3, image="registry/img:tag", message="m"
        )
        start, end, block_text = _resolve_block_for_finding(finding, Path("f.go"), lines, 0, {})
        assert (start, end) == (1, 4)
        assert "RELATED_IMAGE_FOO" in block_text

    def test_non_source_file_is_same_line_only(self):
        lines = ["# RELATED_IMAGE_FOO", "image: quay.io/org/img:v1"]
        finding = Finding(
            severity="blocker",
            file="f.yaml",
            line=2,
            image="quay.io/org/img:v1",
            message="m",
        )
        start, end, block_text = _resolve_block_for_finding(finding, Path("f.yaml"), lines, 0, {})
        assert (start, end) == (2, 2)
        assert block_text == lines[1]

    def test_image_not_on_its_line_falls_back_to_same_line(self):
        lines = ['getEnvOrDefault(\n    "RELATED_IMAGE_FOO",\n    "irrelevant",\n)']
        finding = Finding(
            severity="blocker",
            file="f.go",
            line=1,
            image="registry/does-not-appear:tag",
            message="m",
        )
        start, end, block_text = _resolve_block_for_finding(finding, Path("f.go"), lines, 0, {})
        assert (start, end) == (1, 1)
        assert block_text == lines[0]

    def test_file_index_cache_is_reused_across_calls(self):
        lines = [
            "x := getEnvOrDefault(",
            '    "RELATED_IMAGE_FOO",',
            '    "registry/img-a:tag",',
            ")",
        ]
        finding = Finding(
            severity="blocker", file="f.go", line=3, image="registry/img-a:tag", message="m"
        )
        cache = {}
        _resolve_block_for_finding(finding, Path("f.go"), lines, 0, cache)
        assert Path("f.go") in cache
        pairs_first_call = cache[Path("f.go")]
        _resolve_block_for_finding(finding, Path("f.go"), lines, 0, cache)
        assert cache[Path("f.go")] is pairs_first_call


class TestDowngradeConfirmedRelatedImageFindingsDirectly:
    """Direct unit tests for defensive branches not reachable through run()'s
    normal scan-then-downgrade pipeline (a file scan_file() already read
    successfully cannot become unreadable again in the same run)."""

    def test_missing_file_leaves_finding_blocker(self, tmp_path):
        finding = Finding(
            severity="blocker", file="missing.go", line=1, image="registry/img:tag", message="m"
        )
        result = RuleResult(rule="no-image-tags", passed=False, findings=[finding])
        _downgrade_confirmed_related_image_findings(result, tmp_path, {"RELATED_IMAGE_FOO"})
        assert finding.severity == "blocker"

    def test_line_number_out_of_range_leaves_finding_blocker(self, tmp_path):
        f = tmp_path / "main.go"
        f.write_text("only one line")
        finding = Finding(
            severity="blocker", file="main.go", line=99, image="registry/img:tag", message="m"
        )
        result = RuleResult(rule="no-image-tags", passed=False, findings=[finding])
        _downgrade_confirmed_related_image_findings(result, tmp_path, {"RELATED_IMAGE_FOO"})
        assert finding.severity == "blocker"

    def test_image_not_found_on_its_own_line_stays_blocker(self, tmp_path):
        # finding.image doesn't literally appear on finding.line -- the block
        # search is skipped entirely (no unverifiable column guess), so the
        # same-line-only check runs instead and finds nothing on that line.
        f = tmp_path / "main.go"
        f.write_text('getEnvOrDefault(\n    "RELATED_IMAGE_FOO",\n    "irrelevant text",\n)\n')
        finding = Finding(
            severity="blocker",
            file="main.go",
            line=3,
            image="registry/does-not-appear:tag",
            message="m",
        )
        result = RuleResult(rule="no-image-tags", passed=False, findings=[finding])
        _downgrade_confirmed_related_image_findings(result, tmp_path, {"RELATED_IMAGE_FOO"})
        assert finding.severity == "blocker"


class TestDocumentationFieldDowngrade:
    """``scan_file`` / ``_emit_finding`` severity for documentation-field lines.

    Line-set geometry is covered in ``test_yaml_documentation_fields.py``.
    """

    def test_real_image_field_remains_blocker(self, tmp_path):
        f = tmp_path / "deploy.yaml"
        f.write_text("image: quay.io/org/img:v1.0\n")
        findings = scan_file(f, tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "blocker"
        assert findings[0].image == "quay.io/org/img:v1.0"
        assert "[documentation field]" not in findings[0].message

    def test_default_beside_description_remains_blocker(self, tmp_path):
        f = tmp_path / "crd.yaml"
        f.write_text(
            "properties:\n"
            "  image:\n"
            "    description: |-\n"
            "      Example image ghcr.io/example/tool:latest for docs only.\n"
            "    default: quay.io/org/runtime:v1.2.3\n"
        )
        findings = scan_file(f, tmp_path)
        by_image = {finding.image: finding for finding in findings}
        assert "quay.io/org/runtime:v1.2.3" in by_image
        assert by_image["quay.io/org/runtime:v1.2.3"].severity == "blocker"
        assert "[documentation field]" not in by_image["quay.io/org/runtime:v1.2.3"].message
        assert "ghcr.io/example/tool:latest" in by_image
        assert by_image["ghcr.io/example/tool:latest"].severity == "info"
        assert "[documentation field]" in by_image["ghcr.io/example/tool:latest"].message

    def test_invalid_yaml_with_tagged_image_remains_blocker(self, tmp_path):
        f = tmp_path / "broken.yaml"
        f.write_text(
            "description: |-\n"
            "  docs ghcr.io/org/docs:latest\n"
            "image: quay.io/org/img:v1\n"
            "  bad-indent: true\n"
        )
        findings = scan_file(f, tmp_path)
        by_image = {finding.image: finding for finding in findings}
        assert "quay.io/org/img:v1" in by_image
        assert by_image["quay.io/org/img:v1"].severity == "blocker"
        assert "[documentation field]" not in by_image["quay.io/org/img:v1"].message
        # Parse failure disables docs filter: description-body match stays blocker too.
        assert "ghcr.io/org/docs:latest" in by_image
        assert by_image["ghcr.io/org/docs:latest"].severity == "blocker"
        assert "[documentation field]" not in by_image["ghcr.io/org/docs:latest"].message


class TestDocumentationFieldKnownLimitation:
    """Line-granular docs detection: a real `image` key on the same physical
    line as a docs key in flow-style YAML is also downgraded.

    Idiomatic Kubernetes/CRD YAML is block-style, so this is rare. If this
    test starts failing, column-range tracking may be worth the complexity.
    """

    def test_flow_style_same_line_key_shares_docs_downgrade(self, tmp_path):
        f = tmp_path / "flow.yaml"
        f.write_text('{description: "See quay.io/org/doc:v1", image: quay.io/org/real:v2}\n')
        findings = scan_file(f, tmp_path)
        by_image = {finding.image: finding for finding in findings}
        assert by_image["quay.io/org/real:v2"].severity == "info"
