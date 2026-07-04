def test_import_success_with_yes(run_cli, gt_source_repo, scanner_dest):
    result = run_cli(
        ["import-published-gt", "--realvuln-path", str(gt_source_repo), "--yes"],
        cwd=scanner_dest,
    )
    assert result.returncode == 0, result.stderr
    findings = scanner_dest / "ground-truth" / "findings"
    assert (findings / "realvuln-alpha-human-py" / "ground-truth.json").is_file()
    assert (scanner_dest / "ground-truth" / "slices" / "all.yaml").is_file()


def test_import_dirty_tree_refused(run_cli, gt_source_repo, scanner_dest):
    (gt_source_repo / "dirty.txt").write_text("uncommitted")
    result = run_cli(
        ["import-published-gt", "--realvuln-path", str(gt_source_repo), "--yes"],
        cwd=scanner_dest,
    )
    assert result.returncode == 1
    assert "dirty" in result.stderr.lower()


def test_import_nonempty_target_without_force(run_cli, gt_source_repo, scanner_dest):
    (scanner_dest / "ground-truth" / "findings" / "preexisting").mkdir()
    result = run_cli(
        ["import-published-gt", "--realvuln-path", str(gt_source_repo), "--yes"],
        cwd=scanner_dest,
    )
    assert result.returncode == 1
    assert "force" in result.stderr.lower()


def test_import_non_git_path_exit2(run_cli, tmp_path, scanner_dest):
    plain = tmp_path / "plain"
    plain.mkdir()
    result = run_cli(
        ["import-published-gt", "--realvuln-path", str(plain), "--yes"],
        cwd=scanner_dest,
    )
    assert result.returncode == 2
