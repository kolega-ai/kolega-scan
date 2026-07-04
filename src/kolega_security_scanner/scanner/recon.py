"""Per-repo security recon — a shared, cached threat-model map (library layer).

Stage 1 of the two-stage (recon -> verify) approach: deterministically enumerate
Python HTTP endpoints, then make ONE batched LLM call per chunk that (a) establishes
the app's access model from the full endpoint list, and (b) classifies each
endpoint's security posture. The result is cached per repo and reused by any
recon-consuming detector, so the expensive pass is amortised across detectors.

This module lives in the ``scanner`` (library) layer so the engine can build recon
and inject it into ``DetectorContext`` without importing detector internals.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from kolega_security_scanner.scanner.recon_enumerate import (
    Candidate,
    _enumerate_candidates,
)

if TYPE_CHECKING:
    from kolega_security_scanner.llm.client import LLMClient
    from kolega_security_scanner.scanner.models import ScanTarget

# Module-level cache: repo_root (resolved str) -> ReconResult. Recon is pure
# w.r.t. a repo snapshot, so detectors in the same process share one pass.
_RECON_CACHE: dict[str, ReconResult] = {}

_PY_SKIP_SEGMENTS = (
    "/.git/",
    "/__pycache__/",
    "/node_modules/",
    "/venv/",
    "/.venv/",
    "/env/",
    "/site-packages/",
    "/migrations/",
    "/tests/",
    "/test/",
    "/.tox/",
    "/build/",
)

# LLM output budget is bounded; keep each chunk small enough that the model
# can emit a verdict per endpoint without truncating.
_CHUNK_SIZE = 30


@dataclass(frozen=True)
class EndpointRecon:
    """One endpoint's recon classification (LLM-assigned over a deterministic seed)."""

    file: str
    line: int
    end_line: int
    name: str
    handler_kind: str
    sensitive: bool = False
    anon_reachable: bool = False
    has_auth_gate: bool = False
    is_gate_helper: bool = False
    intended_access: str = "unknown"  # public | authenticated | admin | internal | unknown
    missing_auth: bool = False
    # IDOR signals (cluster: user_controlled_resource_id_without_ownership_check).
    reads_user_resource: bool = False  # selects a record by a request-controlled id
    has_ownership_check: bool = False  # binds the access to the current user / owner
    idor_risk: bool = False  # verdict: reads_user_resource ∧ ¬has_ownership_check ∧ sensitive
    reasoning: str = ""


@dataclass(frozen=True)
class ReconResult:
    """The per-repository recon map: classified endpoints + build status."""

    repo: str
    endpoints: tuple[EndpointRecon, ...] = ()
    status: str = "ok"  # ok | no_llm | no_candidates | partial:<detail>
    llm_calls: int = 0

    def missing_auth_endpoints(self) -> tuple[EndpointRecon, ...]:
        """Endpoints the recon flagged as genuinely missing auth (gate helpers excluded)."""
        return tuple(e for e in self.endpoints if e.missing_auth and not e.is_gate_helper)

    def idor_risk_endpoints(self) -> tuple[EndpointRecon, ...]:
        """IDOR-risk endpoints: user resource by id, no ownership check (gate helpers excluded)."""
        return tuple(e for e in self.endpoints if e.idor_risk and not e.is_gate_helper)


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

_SYSTEM = (
    "You are a senior application-security reviewer performing reconnaissance on "
    "a web app. You reason about the whole app's access model before judging any "
    "single endpoint. Output STRICT JSON only — no prose, no markdown fences."
)

_RUBRIC = """\
You are given EVERY HTTP endpoint/handler candidate in one repository (a numbered
list with code). First build the app's access model in your head: which routes
are intentionally public, which require authentication, which are admin/internal,
and what auth mechanism the app uses (decorators, middleware/before_request, DRF
permission_classes, inline session/JWT checks, or a shared gate-helper function).

Then classify EACH candidate for the cluster "missing authentication/authorization
on a sensitive endpoint" (CWE-862/CWE-306).

For each candidate return these fields:
- "sensitive": true if it performs a state-changing or data-exposing operation
  (create/update/delete, read of another user's data, admin/config, money, PII).
  false if read-only-harmless or static.
- "anon_reachable": true if an UNAUTHENTICATED attacker can invoke it.
- "has_auth_gate": true if ANY authentication/authorization check protects it —
  a decorator (@login_required/@permission_required/Depends(...auth)), middleware
  / before_request, DRF permission_classes, an inline session/JWT/role check, OR
  the handler CALLS a gate/permission helper. A check being weak still counts as
  PRESENT.
- "is_gate_helper": true if THIS function exists to perform an auth/permission/
  trust decision FOR OTHER handlers (e.g. `_wrk_gate(request)`, `require_role`,
  `check_token`). These are infrastructure, not endpoints.
- "intended_access": one of "public","authenticated","admin","internal","unknown".
- "missing_auth": THE VERDICT (cluster missing-auth). true ONLY when ALL hold:
  sensitive==true AND anon_reachable==true AND has_auth_gate==false AND
  is_gate_helper==false.
- "reads_user_resource": true if the handler selects/loads/mutates a specific record
  by an identifier taken from the REQUEST (path/query/body param, e.g. /users/<id>,
  ?account=, body["paste_id"]) — i.e. the caller names which object to act on.
- "has_ownership_check": true if the handler ties that access to the CURRENT user /
  owner (filters by request.user / session user, compares record.owner_id to the
  caller, scopes the query to the authenticated principal, or a permission check that
  enforces ownership). A plain login check that does NOT scope to the owner does NOT
  count.
- "idor_risk": THE VERDICT (cluster IDOR / insecure direct object reference). true
  ONLY when ALL hold: reads_user_resource==true AND has_ownership_check==false AND
  sensitive==true AND is_gate_helper==false. This is an authenticated user reaching
  ANOTHER user's object because the id is trusted without an ownership binding.
- "reasoning": <=1 sentence with file:line evidence.

CRITICAL — IDOR false positives to avoid (there are planted FP traps):
A. If the query/access is already scoped to the current user (filter(owner=request.user),
   WHERE user_id=session_uid, get_object_or_404(..., owner=request.user)) -> has_ownership_check
   true -> NOT idor_risk.
B. Public/non-user-owned lookups (global catalog, public post by slug, reference data)
   are not "reads_user_resource" of a *user* resource -> not idor_risk.
C. Creating a new object (no existing id selected) is not idor_risk.

CRITICAL — avoid these false positives:
1. A gate-helper function (is_gate_helper=true) is NEVER missing_auth — it IS the
   auth mechanism, even if it only checks an internal token / custom header. Do
   not flag it; do not treat an internal-token/header check as "no auth".
2. An endpoint that CALLS a gate helper, or sits behind middleware / a router
   prefix that enforces auth, has_auth_gate=true -> NOT missing_auth.
3. Intentionally public endpoints (login, register, password-reset request,
   health/metrics, OAuth callback, HMAC-verified webhook) are NOT missing_auth.
4. Read-only/harmless endpoints are not "sensitive".
5. Prefer the app's prevailing pattern: if most sensitive routes share a guard and
   a few do not, those few are the real missing_auth findings.

OUTPUT (JSON object, exactly):
{"endpoints":[{"idx":<int>,"sensitive":<bool>,"anon_reachable":<bool>,
"has_auth_gate":<bool>,"is_gate_helper":<bool>,"intended_access":"<str>",
"missing_auth":<bool>,"reads_user_resource":<bool>,"has_ownership_check":<bool>,
"idor_risk":<bool>,"reasoning":"<str>"}]}
"""


def _candidate_block(idx: int, c: Candidate) -> str:
    body = (c.body_text or "").strip()
    if len(body) > 700:
        body = body[:700] + "\n    ...(truncated)"
    dec = (c.decorator_text or "").strip()
    signals = []
    if c.decorator_auth_present or c.inline_auth_present:
        signals.append("auth_signal_present")
    if c.sensitive_by_token:
        signals.append("sensitive_token")
    if c.public_by_token:
        signals.append("public_token")
    if c.authz_sensitive:
        signals.append("authz_sensitive")
    if c.module_has_before_request:
        signals.append("module_before_request")
    sig = ",".join(signals) or "none"
    return (
        f"[{idx}] {c.file_rel}:{c.line}-{c.end_line} fn={c.name} kind={c.handler_kind} "
        f"signals=[{sig}]\n"
        f"  decorators: {dec or '(none)'}\n"
        f"  body:\n    " + body.replace("\n", "\n    ")
    )


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


def _enumerate_repo(repo_root: Path) -> list[Candidate]:
    cands: list[Candidate] = []
    seen: set[tuple[str, int, str]] = set()
    for py in repo_root.rglob("*.py"):
        s = str(py).replace("\\", "/")
        if any(seg in s for seg in _PY_SKIP_SEGMENTS):
            continue
        if not py.is_file():
            continue
        try:
            src = py.read_text(errors="replace")
        except OSError:
            continue
        try:
            enumerated = _enumerate_candidates(py, src, repo_root)
        except Exception:  # noqa: BLE001 - skip unparseable files
            continue
        for c in enumerated:
            key = (c.file_rel, c.line, c.name)
            if key not in seen:
                seen.add(key)
                cands.append(c)
    return cands


# ---------------------------------------------------------------------------
# Recon driver
# ---------------------------------------------------------------------------


def build_recon(
    target: ScanTarget | Path, llm: LLMClient | None, *, use_cache: bool = True
) -> ReconResult:
    """Enumerate endpoints and classify them via one batched LLM call per chunk.

    ``target`` is a ``ScanTarget`` (preferred) or a repo-root ``Path`` (back-compat
    for legacy callers). ``llm`` must expose ``chat_json(messages, max_tokens=...)``;
    ``None`` yields a ``no_llm`` result. Never raises: a missing client or LLM/JSON
    failure yields a degraded ``ReconResult`` (``status`` records why) so callers
    degrade gracefully.
    """
    repo_root = target if isinstance(target, Path) else target.repo_root
    key = str(repo_root.resolve())
    if use_cache and key in _RECON_CACHE:
        return _RECON_CACHE[key]

    cands = _enumerate_repo(repo_root)
    if not cands:
        result = ReconResult(repo=repo_root.name, status="no_candidates")
        if use_cache:
            _RECON_CACHE[key] = result
        return result
    if llm is None:
        result = ReconResult(repo=repo_root.name, status="no_llm")
        if use_cache:
            _RECON_CACHE[key] = result
        return result

    verdict_by_idx: dict[int, dict[str, Any]] = {}
    statuses: list[str] = []
    llm_calls = 0
    for start in range(0, len(cands), _CHUNK_SIZE):
        chunk = cands[start : start + _CHUNK_SIZE]
        blocks = "\n\n".join(_candidate_block(start + i, c) for i, c in enumerate(chunk))
        user = f"{_RUBRIC}\n\n## CANDIDATES ({len(chunk)})\n\n{blocks}"
        try:
            data = llm.chat_json(
                messages=[
                    {"role": "system", "content": _SYSTEM},
                    {"role": "user", "content": user},
                ],
                max_tokens=8000,
            )
        except Exception as exc:  # noqa: BLE001 - record + continue, never fatal
            statuses.append(f"exc:{type(exc).__name__}")
            continue
        llm_calls += 1
        rows = data.get("endpoints") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            statuses.append("no_json")
            continue
        for r in rows:
            if isinstance(r, dict) and isinstance(r.get("idx"), int):
                verdict_by_idx[r["idx"]] = r
        statuses.append("ok")

    endpoints: list[EndpointRecon] = []
    for i, c in enumerate(cands):
        v = verdict_by_idx.get(i, {})
        endpoints.append(
            EndpointRecon(
                file=c.file_rel,
                line=c.line,
                end_line=c.end_line,
                name=c.name,
                handler_kind=c.handler_kind,
                sensitive=bool(v.get("sensitive")),
                anon_reachable=bool(v.get("anon_reachable")),
                has_auth_gate=bool(v.get("has_auth_gate")),
                is_gate_helper=bool(v.get("is_gate_helper")),
                intended_access=str(v.get("intended_access", "unknown")),
                missing_auth=bool(v.get("missing_auth")),
                reads_user_resource=bool(v.get("reads_user_resource")),
                has_ownership_check=bool(v.get("has_ownership_check")),
                idor_risk=bool(v.get("idor_risk")),
                reasoning=str(v.get("reasoning", ""))[:240],
            )
        )

    status = "ok"
    if statuses and all(s != "ok" for s in statuses):
        status = "partial:" + ",".join(sorted(set(statuses)))
    elif any(s != "ok" for s in statuses):
        status = "partial:" + ",".join(sorted({s for s in statuses if s != "ok"}))

    result = ReconResult(
        repo=repo_root.name,
        endpoints=tuple(endpoints),
        status=status,
        llm_calls=llm_calls,
    )
    if use_cache:
        _RECON_CACHE[key] = result
    return result


def clear_cache() -> None:
    """Drop all cached recon results (test isolation / long-lived processes)."""
    _RECON_CACHE.clear()
