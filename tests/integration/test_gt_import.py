import yaml

from kolega_security_scanner.groundtruth.importer import import_published_gt
from kolega_security_scanner.groundtruth.slices import resolve_slice
from kolega_security_scanner.groundtruth.validator import validate_gt_dir


def test_import_end_to_end(gt_source_repo, scanner_dest):
    result = import_published_gt(gt_source_repo, scanner_dest, force=False)

    assert result.repos == 4
    assert result.validated == 4
    assert result.failed == 0

    findings = scanner_dest / "ground-truth" / "findings"
    assert {p.name for p in findings.iterdir() if p.is_dir()} == {
        "realvuln-alpha-human-py",
        "realvuln-bravo-llm-py",
        "realvuln-charlie-human-js",
        "realvuln-delta-llm-ts",
    }

    slices = scanner_dest / "ground-truth" / "slices"
    human = yaml.safe_load((slices / "human-curated.yaml").read_text())["repos"]
    vibe = yaml.safe_load((slices / "vibe-coded-python.yaml").read_text())["repos"]
    js_ts = yaml.safe_load((slices / "js-ts.yaml").read_text())["repos"]

    # orthogonal membership: charlie is human AND js; delta is vibe AND ts
    assert "realvuln-charlie-human-js" in human and "realvuln-charlie-human-js" in js_ts
    assert "realvuln-delta-llm-ts" in vibe and "realvuln-delta-llm-ts" in js_ts
    assert "realvuln-alpha-human-py" in human
    assert "realvuln-bravo-llm-py" in vibe

    # all.yaml composes via include and resolves to the union
    all_repos = resolve_slice("all", slices)
    assert set(all_repos) == {
        "realvuln-alpha-human-py",
        "realvuln-bravo-llm-py",
        "realvuln-charlie-human-js",
        "realvuln-delta-llm-ts",
    }

    log = (scanner_dest / "ground-truth" / "IMPORT_LOG.md").read_text()
    assert "repos=4" in log and "validated=4" in log

    assert all(r.ok for r in validate_gt_dir(findings))
