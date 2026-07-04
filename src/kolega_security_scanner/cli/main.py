"""``kolega-scan`` CLI entry point.

Commands: ``scan``, ``validate-gt``, ``import-published-gt`` (plus ``--version``).
stdout is deterministic and sorted; stderr carries prompts and errors.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Annotated

import typer

from kolega_security_scanner import __version__
from kolega_security_scanner.cli._errors import (
    GtImportError,
    KolegaScannerError,
    UsageError,
    ValidationError,
)
from kolega_security_scanner.cli._exit_codes import (
    EXIT_DOMAIN_FAILURE,
    EXIT_INTERNAL_ERROR,
    EXIT_USAGE_ERROR,
)
from kolega_security_scanner.groundtruth.importer import (
    import_published_gt,
    read_branch_and_sha,
)
from kolega_security_scanner.groundtruth.validator import validate_gt_dir

log = logging.getLogger("kolega_security_scanner.cli")

app = typer.Typer(
    name="kolega-scan",
    help="Kolega Scan — LLM-assisted SAST CLI.",
    add_completion=False,
    no_args_is_help=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"kolega-scan {__version__}")
        raise typer.Exit(code=0)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Print version and exit.",
        ),
    ] = False,
) -> None:
    """Root command. Prints help to stderr and exits 2 when no subcommand given."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help(), err=True)
        raise typer.Exit(code=EXIT_USAGE_ERROR)


@app.command("scan")
def scan(
    repo_path: Annotated[Path, typer.Argument(help="Path to the repository to scan.")],
    out: Annotated[Path | None, typer.Option("--out", help="Write Finding JSON here.")] = None,
    config_path: Annotated[
        Path | None, typer.Option("--config", help="Optional YAML config.")
    ] = None,
    clusters: Annotated[
        str | None, typer.Option("--clusters", help="Comma-separated cluster subset.")
    ] = None,
    detectors: Annotated[
        str | None, typer.Option("--detectors", help="Comma-separated detector-slug subset.")
    ] = None,
    scanner: Annotated[
        str,
        typer.Option(
            "--scanner",
            help="Which version to run: kolega-scan-oss-v1 (default, 2-model) or "
            "kolega-scan-oss-v2 (3-model, needs MOONSHOT_API_KEY too). External "
            "scanners register under the 'kolega_security_scanner.scanners' "
            "entry-point group.",
        ),
    ] = "kolega-scan-oss-v1",
    recon: Annotated[
        bool | None,
        typer.Option(
            "--recon/--no-recon",
            help="Build the LLM-backed recon map and feed it to recon-aware detectors. "
            "Default: on, but only active when an LLM is available.",
        ),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Verbose (DEBUG) progress on stderr.")
    ] = False,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Only warnings/errors on stderr.")
    ] = False,
) -> None:
    """Scan a repository and emit Semgrep-compatible Finding JSON.

    Progress is written to stderr; the Finding JSON goes to stdout (or --out), so the
    two never mix. Use -v for per-step detail or -q to silence progress.
    """
    from kolega_security_scanner.cli._errors import (
        KolegaScannerError,
        LLMConfigError,
        UsageError,
    )
    from kolega_security_scanner.cli._logging import configure_logging

    configure_logging(verbosity=(1 if verbose else -1 if quiet else 0))
    from kolega_security_scanner.scanner import output as _output
    from kolega_security_scanner.scanner.config import ScanConfig
    from kolega_security_scanner.scanner.providers import default_provider_registry

    if not repo_path.is_dir():
        typer.echo(f"not a directory: {repo_path}", err=True)
        raise typer.Exit(code=EXIT_USAGE_ERROR)

    # Optional YAML config; explicit CLI flags take precedence over config values.
    file_cfg: dict[str, object] = {}
    if config_path is not None:
        import yaml

        if not config_path.is_file():
            typer.echo(f"config not found: {config_path}", err=True)
            raise typer.Exit(code=EXIT_USAGE_ERROR)
        file_cfg = yaml.safe_load(config_path.read_text()) or {}

    def _subset(cli_val: str | None, key: str) -> tuple[str, ...] | None:
        if cli_val:
            return tuple(s.strip() for s in cli_val.split(","))
        raw = file_cfg.get(key)
        if raw is None:
            return None
        items = raw if isinstance(raw, list) else str(raw).split(",")
        return tuple(str(s).strip() for s in items)

    eff_out = out or (Path(str(file_cfg["out"])) if file_cfg.get("out") else None)
    # Recon is ON by default. Explicit --recon/--no-recon wins; else fall back to the
    # config file, defaulting to on. ``recon is True`` (the user typed --recon) is an
    # explicit demand and is enforced below; the default-on case degrades silently.
    eff_recon = recon if recon is not None else bool(file_cfg.get("recon", True))
    cfg = ScanConfig(
        repo_path=repo_path,
        clusters=_subset(clusters, "clusters"),
        detectors=_subset(detectors, "detectors"),
        out=eff_out,
        recon=eff_recon,
        # The user typing --recon is an explicit demand; providers that honor recon
        # fail fast when it cannot run. The default-on case degrades silently.
        recon_explicit=recon is True,
    )

    # Resolve the scan provider early so an unknown --scanner fails fast (exit 2).
    # The CLI is LLM-agnostic: whether (and how) a scanner uses an LLM is the
    # scanner's own business — a provider missing its credentials raises
    # LLMConfigError, which maps to a usage error below.
    try:
        provider = default_provider_registry().get(scanner)
    except UsageError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=EXIT_USAGE_ERROR) from exc

    log.info("scanning %s with '%s'", repo_path, scanner)
    try:
        result = provider.scan(cfg)
    except LLMConfigError as exc:
        # e.g. a scanner that needs an LLM but has no key, or an explicit --recon
        # without an available LLM: usage/config error, fail fast.
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=EXIT_USAGE_ERROR) from exc
    except UsageError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=EXIT_USAGE_ERROR) from exc
    except KolegaScannerError as exc:
        typer.echo(f"internal error: {exc}", err=True)
        raise typer.Exit(code=EXIT_INTERNAL_ERROR) from exc

    for err in result.detector_errors:
        typer.echo(f"detector {err.slug} failed (isolated): {err.message}", err=True)

    log.info("scan complete: %d findings", len(result.findings))
    payload = _output.dumps(result)
    if eff_out:
        eff_out.write_text(payload)
    else:
        typer.echo(payload, nl=False)


@app.command("validate-gt")
def validate_gt(
    gt_path: Annotated[Path, typer.Argument(help="GT directory or ground-truth.json.")],
) -> None:
    """Validate every ground-truth file under a path. Sorted OK lines to stdout."""
    try:
        results = validate_gt_dir(gt_path)
    except ValidationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=EXIT_USAGE_ERROR) from exc

    failed = False
    for result in results:
        if result.ok:
            typer.echo(f"OK {result.path}")
        else:
            failed = True
            for err in result.errors:
                typer.echo(f"{result.path}: {err}", err=True)
    if failed:
        raise typer.Exit(code=EXIT_DOMAIN_FAILURE)


@app.command("import-published-gt")
def import_published_gt_cmd(
    realvuln_path: Annotated[
        Path, typer.Option("--realvuln-path", help="Path to RealVulnBenchmark.")
    ] = Path("../RealVulnBenchmark"),
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite a non-empty findings dir.")
    ] = False,
    yes: Annotated[
        bool, typer.Option("--yes", help="Skip the branch-confirmation prompt.")
    ] = False,
) -> None:
    """Import the published RealVulnBenchmark GT with slice manifests."""
    try:
        branch, short_sha = read_branch_and_sha(realvuln_path)
    except UsageError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=EXIT_USAGE_ERROR) from exc

    typer.echo(f"branch {branch}")
    typer.echo(f"sha {short_sha}")

    if not yes:
        answer = typer.prompt(
            f"Proceed with branch {branch} @ {short_sha}? [y/N]",
            default="N",
            show_default=False,
        )
        if answer.strip().lower() != "y":
            typer.echo("aborted", err=True)
            raise typer.Exit(code=0)

    try:
        result = import_published_gt(realvuln_path, ".", force=force)
    except GtImportError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=EXIT_DOMAIN_FAILURE) from exc
    except KolegaScannerError as exc:
        typer.echo(f"internal error: {exc}", err=True)
        raise typer.Exit(code=EXIT_INTERNAL_ERROR) from exc

    for repo in sorted(result.copied):
        typer.echo(f"copied {repo}")
    typer.echo(
        f"imported {result.repos} repos, validated {result.validated}, failed {result.failed}"
    )
    for failure in result.failures:
        typer.echo(failure, err=True)
    if result.failed:
        raise typer.Exit(code=EXIT_DOMAIN_FAILURE)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
