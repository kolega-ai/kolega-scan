from kolega_security_scanner.scanner.enumerate import enumerate_sources


def test_includes_sources_skips_vendor_and_binary(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.ts").write_text("const x = 1;\n")
    (tmp_path / "README.md").write_text("# doc\n")
    nm = tmp_path / "node_modules" / "dep"
    nm.mkdir(parents=True)
    (nm / "c.js").write_text("vendor")
    (tmp_path / "blob.py").write_bytes(b"\x00\x01binary")
    target = enumerate_sources(tmp_path)
    paths = {sf.path for sf in target.files}
    assert "a.py" in paths and "b.ts" in paths
    assert "README.md" not in paths
    assert not any("node_modules" in p for p in paths)
    assert "blob.py" not in paths


def test_skips_minified_files_with_overlong_lines(tmp_path):
    # A minified bundle: small enough to pass MAX_BYTES but with one enormous
    # line that triggers catastrophic regex backtracking in detectors.
    (tmp_path / "app.js").write_text("const x = 1;\n")
    (tmp_path / "bundle.min.js").write_text("var a=1;" + "a;" * 20_000 + "\n")
    paths = {sf.path for sf in enumerate_sources(tmp_path).files}
    assert "app.js" in paths
    assert "bundle.min.js" not in paths


def test_skip_minified_false_keeps_overlong_lines(tmp_path):
    # LLM-only scanners opt out of the ReDoS minified-skip to keep dense single-file
    # apps (e.g. dsvw.py) whose long lines would otherwise be excluded.
    (tmp_path / "dense.py").write_text("x = '" + "a" * 9_000 + "'\n")
    skipped = {sf.path for sf in enumerate_sources(tmp_path).files}
    kept = {sf.path for sf in enumerate_sources(tmp_path, skip_minified=False).files}
    assert "dense.py" not in skipped
    assert "dense.py" in kept


def test_language_tagging(tmp_path):
    (tmp_path / "a.py").write_text("x=1")
    (tmp_path / "a.tsx").write_text("x")
    langs = {sf.path: sf.language for sf in enumerate_sources(tmp_path).files}
    assert langs["a.py"] == "python"
    assert langs["a.tsx"] == "typescript"
