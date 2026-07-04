"""Prompt templates for the claude-adaptation pipeline.

Every prompt follows the article's guidance: give the model GOAL and CONTEXT (not a
prescriptive checklist), demand STRUCTURED output whose fields are ordered so reasoning
builds progressively (rationale -> finding -> impact -> severity), and include an escape
hatch so weak findings are flagged rather than fabricated. The verifier prompt is
adversarial: it is told to assume the finding is a false positive and try to disprove it.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Phase 1 — Threat modeling (code-driven derivation; human interview omitted)
# ---------------------------------------------------------------------------

THREAT_MODEL_SYSTEM = (
    "You are a senior application-security architect. You build a concise threat "
    "model from source code before any vulnerability hunting begins. You reason "
    "about the WHOLE system's purpose, assets, entry points, and trust boundaries. "
    "Output STRICT JSON only — no prose, no markdown fences."
)

THREAT_MODEL_RUBRIC = """\
You are given a map of a repository (file tree + selected entry-point source). Derive a
threat model answering Shostack's first two questions: "What are we building?" and "What
can go wrong?". Do NOT enumerate specific bugs yet — that is a later phase.

Return JSON exactly:
{
  "summary": "<=2 sentences: what this system is and does",
  "assets": ["data/capabilities worth protecting, e.g. user PII, auth tokens, money"],
  "entry_points": ["where untrusted input enters: HTTP routes, CLI args, file uploads, queues"],
  "trust_boundaries": ["where trust level changes: anon->authed, user->admin, app->db/shell"],
  "trusted_inputs": ["inputs legitimately trusted in THIS system (config files,
      authenticated clients) — used later to suppress false positives"],
  "vuln_classes": ["the 4-8 vulnerability classes MOST relevant to this system's
      language / framework / assets"]
}
"""

# ---------------------------------------------------------------------------
# Phase 3 — Discovery (maximize recall; structured output with escape hatch)
# ---------------------------------------------------------------------------

DISCOVERY_SYSTEM = (
    "You are an expert security researcher hunting for real, exploitable "
    "vulnerabilities in source code. Your goal is RECALL: surface every plausible "
    "candidate, but be honest about confidence — flag weak hunches as low confidence "
    "rather than inventing certainty. Output STRICT JSON only — no prose, no fences."
)

DISCOVERY_RUBRIC = """\
GOAL: Find vulnerabilities an attacker could exploit in the code below. Use the threat
model to focus on what matters for THIS system, but you may report anything genuinely
dangerous. Reason about how untrusted input reaches a dangerous sink.

CHECKLIST — a comprehensive audit covers EVERY class below, not just the classic
injections. For a WEB / APPLICATION codebase the misconfiguration, access-control,
auth-hardening, and data-exposure families are the MOST COMMON real findings. For a
NATIVE codebase (C/C++) that parses untrusted bytes — file formats, network packets,
decoders, codecs — the MEMORY SAFETY family below is the dominant real-bug class: hunt it
first and hardest. Consider each (skip only those that genuinely do not apply; do NOT
fabricate). For each, check whether the control is missing / the untrusted input reaches
the sink:

MEMORY SAFETY (C/C++ parsers of untrusted input — the dominant native-code bug class)
- Heap/stack buffer overflow — a length, count, size, or offset field read FROM the input
  is trusted and used to memcpy / index / loop / write without bounds-checking against the
  real allocation (CWE-787 OOB write, CWE-125 OOB read, CWE-120/121/122)
- Improper array index validation — input-controlled index into a fixed-size array, e.g. a
  channel/element count exceeding a MAX_* without a guard (CWE-129)
- Integer overflow / wraparound feeding an allocation or size math — count * elem_size,
  size + extra, or a multiply/add that wraps, yielding an undersized or wild malloc that a
  later copy overflows (CWE-190/191/680)
- Use-after-free / double-free — object freed on one path (error, sentinel, early return)
  then read or freed again; freed-then-written (CWE-416/415)
- NULL-pointer dereference — a pointer left NULL by a partial/failed parse, then
  dereferenced for read or write (CWE-476)
- Type confusion / uninitialized read — struct-overlay on raw bytes without validating a
  discriminant; reading a field before it is set (CWE-843/457)
- Format-string — input flows into the format argument of printf-family (CWE-134)
For memory-safety findings, trace: which INPUT FIELD (size/count/offset/index) is trusted,
where it is used (the sink: memcpy/alloc/array-index/free), and why no check bounds it.

INJECTION & EXECUTION
- SQL (CWE-89), NoSQL (CWE-943), OS/command (CWE-78/77), code/eval (CWE-94/95),
  template/SSTI — render_template_string, Jinja from string (CWE-1336/94), XPath (CWE-643),
  log injection (CWE-117), HTTP header/response splitting (CWE-113), CSV/formula injection
  in spreadsheet EXPORTS — cells starting with = + @ - (CWE-1236)
- Insecure deserialization — pickle/yaml.load/marshal/jsonpickle on untrusted data (CWE-502)
FILE & PATH
- Path traversal / arbitrary file read or write (CWE-22/73)
- Unrestricted / unvalidated file upload — trusts client content-type or extension only,
  no content validation (CWE-434)
- SSRF — user-controlled URL fetched server-side, incl. admin/webhook URLs (CWE-918)
XSS
- Reflected, stored, and DOM XSS — unescaped user data in HTML/JS, |safe, mark_safe,
  innerHTML, autoescape off (CWE-79)
ACCESS CONTROL (very common — check EVERY state-changing or data-returning view)
- Missing authentication on a sensitive route (CWE-306)
- Missing authorization / function-level / role checks (CWE-862); privilege/role
  escalation, self-assigned roles at registration (CWE-269/863)
- IDOR / BOLA — object id from request used without an ownership/tenant scope check;
  cross-tenant / cross-user data access (CWE-639)
- Mass assignment — request binds model fields it shouldn't (role, owner, status) (CWE-915)
- Business-logic / object-state gaps — acting on resources out of allowed state (CWE-840/841)
AUTH & SESSION HARDENING (very common)
- Missing rate limiting / brute-force protection on login, registration, password-reset,
  and other auth endpoints (CWE-307/770/799)
- User / account enumeration — login or registration reveals whether an account exists
  (CWE-203/204)
- Weak password reset — guessable/long-lived tokens, token in response/logs, no
  invalidation (CWE-640); session fixation, non-expiring sessions (CWE-384/613)
- Insecure cookie flags — missing Secure / HttpOnly / SameSite (CWE-614/1004); CSRF on
  state-changing routes (CWE-352)
SECRETS & SENSITIVE DATA (very common)
- Hardcoded credentials / API keys / tokens / default framework secret keys — Django
  SECRET_KEY, JWT/HMAC secrets (CWE-798/321)
- Sensitive data / secrets / tokens written to logs or console (CWE-532)
- Sensitive data / PII / credentials stored in plaintext at rest (CWE-312/922)
- Sensitive data exposure in responses, debug pages, verbose errors, DEBUG=True,
  exposed media/debug routes (CWE-200/215/209)
CRYPTO
- Weak hash/cipher, no salt, ECB, hardcoded IV/key (CWE-327/328/916); weak/predictable
  PRNG used for tokens, session ids, password-reset (CWE-330/338)
MISCONFIG & AVAILABILITY (the single most common family)
- DEBUG=True by default, ALLOWED_HOSTS=['*'], permissive CORS '*', disabled TLS verify,
  missing security headers (CWE-16/693/489)
- Denial of service — unbounded file upload / CSV import / in-memory buffering of
  user-controlled size (CWE-400/770)
- Open redirect — user-controlled redirect target (CWE-601); XXE — external entities in
  XML parsing (CWE-611)

For EACH finding, fill these fields IN THIS ORDER so your reasoning builds before you
commit to a verdict:
- "rationale": how untrusted input reaches the sink / why the control is missing (cite code)
- "title": short name of the vulnerability
- "vuln_class": snake_case class, e.g. sql_injection, missing_authorization, ssrf, path_traversal
- "file": exact repo-relative path from the headers below
- "line": the 1-based line number of the SINK or missing-check site (use the numbers shown)
- "impact": what an attacker gains if it is exploited
- "cwe": the single best CWE id, format "CWE-89"
- "severity": one of "critical","high","medium","low","info"
- "confidence": one of "high","medium","low" — your honest confidence it is a TRUE positive

ESCAPE HATCH: if you find nothing exploitable, return {"findings": []}. Do NOT pad with
defensive-in-depth nitpicks or style issues. Report only security-relevant findings.

OUTPUT (JSON object, exactly):
{"findings":[{"rationale":"...","title":"...","vuln_class":"...","file":"...","line":<int>,"impact":"...","cwe":"CWE-...","severity":"...","confidence":"..."}]}
"""

# ---------------------------------------------------------------------------
# Phase 4 — Verification (independent, adversarial: try to DISPROVE the finding)
# ---------------------------------------------------------------------------

VERIFY_SYSTEM = (
    "You are a skeptical security verifier. A separate agent reported a vulnerability; "
    "you have NO knowledge of its reasoning. Assume it is a FALSE POSITIVE and try to "
    "disprove it by searching the code for compensating controls (input validation, auth "
    "gates, type constraints, unreachable code, sanitization, framework protections). "
    "Only confirm if you cannot disprove it. Output STRICT JSON only — no prose, no fences."
)

VERIFY_RUBRIC = """\
A finding was reported. Independently judge whether it is a TRUE positive, using the test
that fits its KIND:
- DATA-FLOW bugs (injection, XSS, SSRF, deserialization, path traversal, IDOR, open
  redirect): TRUE if attacker-influenced input reaches the sink on a reachable path AND no
  compensating control (validation, auth, sanitization, escaping, ownership/tenant scope)
  neutralizes it.
- MISSING-CONTROL / CONFIG bugs (security misconfiguration, DEBUG/ALLOWED_HOSTS/CORS,
  missing authn/authz, missing rate-limiting, insecure cookie flags, missing CSRF,
  hardcoded/default secrets, plaintext storage, secrets in logs, weak crypto/PRNG, user
  enumeration, mass assignment): there is NO input→sink chain — TRUE if the required control
  is genuinely ABSENT or the insecure setting is genuinely PRESENT on a reachable path.
- MEMORY-SAFETY bugs (buffer overflow, OOB read/write, improper array index, integer
  overflow into allocation, use-after-free, double-free, NULL deref, type confusion): TRUE
  if an input-derived size/count/offset/index reaches the memcpy/alloc/array-index/free
  sink AND no bound check, MAX_* clamp, signedness/overflow guard, or NULL check sits
  between them on a reachable path. Verify the GUARD: a check that exists but is on the
  wrong variable, off-by-one, after the use, or trivially bypassable does NOT neutralize it.
  Do not require a runnable exploit — reachable-plus-unbounded is sufficient to confirm.

Mark NOT a true positive only if a control actually exists, the threat model marks the
input/setting as legitimately trusted, the path is unreachable, or it is a cosmetic
defense-in-depth nit with no security impact.

Return JSON exactly:
{
  "reason": "<=2 sentences citing the code evidence for your ruling",
  "severity": "recalibrated severity if you confirm: critical|high|medium|low|info (else null)",
  "exploitable": true|false
}
"""

# ---------------------------------------------------------------------------
# Phase 5 — Triage (model-based dedupe qualification over deterministic buckets)
# ---------------------------------------------------------------------------

DEDUPE_SYSTEM = "You are a security triage lead deduplicating findings. Output STRICT JSON only."

DEDUPE_RUBRIC = """\
The findings below share a (file, vulnerability-class) bucket and are near each other.
Decide whether they are the SAME bug or DISTINCT bugs.

SAME (collapse to one): same root cause rephrased, the same missing global protection,
or cause-and-consequence on one code path.
DISTINCT (keep separate): different variables/inputs reaching the sink, independent bugs
that happen to share a helper, or the same missing check that requires a SEPARATE fix per
site.

Return JSON exactly: {"groups": [[<idx>, <idx>, ...], [<idx>]]}  where each inner list is
one real bug (indices refer to the numbered findings).
"""


def threat_model_user(file_tree: str, entry_source: str) -> str:
    """Compose the Phase 1 user message."""
    return (
        f"{THREAT_MODEL_RUBRIC}\n\n## FILE TREE\n\n{file_tree}\n\n"
        f"## SELECTED ENTRY-POINT SOURCE\n\n{entry_source}"
    )


def discovery_user(threat_model_ctx: str, partition_name: str, code: str) -> str:
    """Compose the Phase 3 user message for one partition."""
    return (
        f"{DISCOVERY_RUBRIC}\n\n## THREAT MODEL\n\n{threat_model_ctx}\n\n"
        f"## PARTITION: {partition_name}\n\n{code}"
    )


def verify_user(threat_model_ctx: str, finding_desc: str, code: str) -> str:
    """Compose the Phase 4 user message for one candidate."""
    return (
        f"{VERIFY_RUBRIC}\n\n## THREAT MODEL\n\n{threat_model_ctx}\n\n"
        f"## REPORTED FINDING\n\n{finding_desc}\n\n## CODE\n\n{code}"
    )


def dedupe_user(findings_block: str) -> str:
    """Compose the Phase 5 dedupe user message for one bucket."""
    return f"{DEDUPE_RUBRIC}\n\n## FINDINGS\n\n{findings_block}"


# ---------------------------------------------------------------------------
# Agentic prompts (kolega-code ask) — the agent NAVIGATES the repo itself, so we
# give it the task + output contract instead of pre-stuffed/truncated code.
# ---------------------------------------------------------------------------

_AGENT_PREAMBLE = (
    "You are auditing the repository at the project root. Use your tools to read and "
    "search the code yourself — do not ask for files. Reply with STRICT JSON only as "
    "the final message: no prose, no markdown fences, no commentary around the JSON."
)


def agent_threat_model() -> str:
    """Phase 1 agentic prompt: explore the repo, emit the threat-model JSON."""
    return f"{_AGENT_PREAMBLE}\n\n{THREAT_MODEL_RUBRIC}"


def agent_discovery(
    threat_model_ctx: str, focus: str | None = None, already_found: str = ""
) -> str:
    """Phase 3 agentic prompt: hunt vulns. ``focus`` scopes the session to one surface.

    ``already_found`` (rounds 2+) lists earlier findings so the agent looks for ADDITIONAL
    distinct vulnerabilities — the article's iterate-until-plateau discovery loop.
    """
    if focus:
        scope = (
            f"FOCUS your audit on the '{focus}' area of the repository: open and read its "
            f"files thoroughly, then follow imports and data flow into OTHER files it calls "
            f"(a sink here may be guarded, or unguarded, elsewhere). Be exhaustive within "
            f"this area — report every applicable checklist class you can substantiate."
        )
    else:
        scope = (
            "Navigate the ENTIRE repository — follow imports and data flow ACROSS files "
            "(a sink in one file may be guarded, or unguarded, in another)."
        )
    more = ""
    if already_found:
        more = (
            "\n\nEARLIER ROUNDS ALREADY FOUND the vulnerabilities listed below. Do NOT "
            "repeat them. Hunt for ADDITIONAL, DISTINCT, GENUINELY-EXPLOITABLE vulns they "
            "missed — other files, other sinks, other classes, other parameters. "
            'CRITICAL: most repos are now exhausted — returning {"findings": []} is the '
            "EXPECTED and CORRECT answer unless you can point to a concrete new sink with "
            "attacker-controlled input. Do NOT pad, do NOT lower your bar, do NOT restate "
            "near-duplicates of the list. A wrong addition is worse than none.\n\n"
            f"## ALREADY FOUND\n{already_found}"
        )
    return (
        f"{_AGENT_PREAMBLE}\n\n{DISCOVERY_RUBRIC}\n\n{_COVERAGE}\n\n{scope} Cite the exact "
        f"repo-relative path and line for each finding.\n\n## THREAT MODEL\n\n"
        f"{threat_model_ctx}{more}"
    )


_COVERAGE = """\
COVERAGE — vulnerabilities are NOT only in .py files. Open and audit EVERY file type:
- HTML / Jinja / Django templates (*.html, *.jinja, *.j2): stored & reflected XSS live HERE,
  not in the view — look for {{ var|safe }}, {% autoescape off %}, mark_safe, |safe filters,
  and user data rendered without escaping. A handler that saves user input is only half the
  bug; the template that renders it unescaped is the sink. AUDIT THE TEMPLATES.
- Settings / config (settings.py, config.py, *.cfg, *.ini, *.toml, *.env, .env*): DEBUG=True,
  ALLOWED_HOSTS=['*'], permissive CORS, hardcoded SECRET_KEY / passwords / API keys, insecure
  cookie flags, disabled CSRF/TLS verification.
- Infra / deploy (*.conf, nginx.conf, Dockerfile, docker-compose*, *.yml): cleartext HTTP/no
  TLS, exposed ports/services, missing security headers, secrets baked into images.
- Seed / fixture / script files (*_seed*, fixtures, management commands): hardcoded default
  credentials and secrets.
- JS / templates served to the browser: DOM XSS, secrets in client code.
Do NOT finish until you have actually opened the template and config files in scope."""


def agent_variants(threat_model_ctx: str, confirmed_block: str) -> str:
    """Phase 6 agentic prompt: find MORE instances of already-confirmed bug patterns."""
    return (
        f"{_AGENT_PREAMBLE}\n\n{DISCOVERY_RUBRIC}\n\n"
        f"VARIANT HUNT: the vulnerabilities below were CONFIRMED real in this repo. Bugs "
        f"cluster — the same mistake is usually repeated. For EACH confirmed pattern, search "
        f"the WHOLE repo for OTHER instances of the SAME class/pattern that were missed: the "
        f"same sink in other files, the same missing control on other endpoints/views, the "
        f"same unsafe helper called elsewhere, the same field/param in sibling handlers. "
        f"Report only NEW locations not in the list (different file or line). If a confirmed "
        f"bug is a repo-wide misconfiguration, do not re-report the same line. Same output "
        f"schema.\n\n## CONFIRMED VULNERABILITIES\n{confirmed_block}\n\n"
        f"## THREAT MODEL\n\n{threat_model_ctx}"
    )


def agent_verify(threat_model_ctx: str, finding_desc: str) -> str:
    """Phase 4 agentic prompt: navigate for compensating controls, then rule."""
    return (
        f"{_AGENT_PREAMBLE}\n\n{VERIFY_RUBRIC}\n\n"
        f"Before ruling, SEARCH the repo for a compensating control the reporter may "
        f"have missed: middleware/before_request, decorators, DRF permission_classes, "
        f"validation/sanitization helpers, ownership checks — they often live in other "
        f"files. Open them and confirm whether they actually cover this code path.\n\n"
        f"## THREAT MODEL\n\n{threat_model_ctx}\n\n## REPORTED FINDING\n\n{finding_desc}"
    )


def agent_verify_batch(threat_model_ctx: str, findings_block: str) -> str:
    """Phase 4 agentic prompt: verify MANY findings (all in one file) in one session."""
    return (
        f"{_AGENT_PREAMBLE}\n\n"
        f"Multiple findings were reported, all in the SAME source file. Read that file and "
        f"the code it calls, then rule on EACH finding INDEPENDENTLY. Be skeptical but use "
        f"the RIGHT test for the finding's KIND — there are two:\n"
        f"(A) DATA-FLOW bugs (injection, XSS, SSRF, deserialization, path traversal, IDOR, "
        f"open redirect): confirm ONLY if attacker-controlled input reaches the sink with NO "
        f"effective intervening control — SEARCH for one (middleware, decorators, DRF "
        f"permission_classes, validation/sanitization, ownership checks, auto-escaping, often "
        f"in OTHER files). If a real control covers it, exploitable=false.\n"
        f"(B) MISSING-CONTROL / CONFIG bugs (security misconfiguration, DEBUG=True, "
        f"ALLOWED_HOSTS/CORS, missing authn/authz, missing rate-limiting/brute-force "
        f"protection, insecure cookie flags, missing CSRF, hardcoded/default secrets, "
        f"plaintext storage, secrets in logs, weak crypto/PRNG, user enumeration, mass "
        f"assignment): these have NO input→sink chain — confirm if the required control is "
        f"genuinely ABSENT (or the insecure setting is genuinely PRESENT) on a reachable "
        f"path. Do NOT reject these just because there is 'no attacker input'.\n"
        f"Reject only genuine noise: a control actually exists, the code is unreachable, or "
        f"it is a cosmetic defense-in-depth nit with no security impact.\n\n"
        f"{VERIFY_RUBRIC}\n\n"
        f'Return JSON exactly: {{"verdicts":[{{"idx":<int>,"exploitable":<bool>,'
        f'"severity":"critical|high|medium|low|info or null","reason":"<=2 sentences"}}]}}'
        f" — one object per reported finding, keyed by its idx.\n\n"
        f"## THREAT MODEL\n\n{threat_model_ctx}\n\n## REPORTED FINDINGS\n\n{findings_block}"
    )


__all__ = [
    "THREAT_MODEL_SYSTEM",
    "DISCOVERY_SYSTEM",
    "VERIFY_SYSTEM",
    "DEDUPE_SYSTEM",
    "threat_model_user",
    "discovery_user",
    "verify_user",
    "dedupe_user",
    "agent_threat_model",
    "agent_discovery",
    "agent_verify",
    "agent_verify_batch",
]
