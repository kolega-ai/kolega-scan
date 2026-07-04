"""Missing-authentication route enumeration for the recon map.

AST pre-screen of route handlers (decorator/route detection, auth/authz decorator
recognition, sensitivity heuristics) followed by an optional LLM verification pass.
Produces candidate endpoints lacking authentication for recon-aware scanning.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

PRIMARY_CWE = "CWE-306"

# A parsed Python function definition (sync or async).
FuncDef = ast.FunctionDef | ast.AsyncFunctionDef


# ---------------------------------------------------------------------------
# Vocab — generic web-framework tokens only.
# ---------------------------------------------------------------------------

ROUTE_DECORATOR_ATTRS = frozenset(
    {
        "route",
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "head",
        "options",
        "websocket",
        "api_route",
        "add_url_rule",
        "view_config",
        "expose",
    }
)

ROUTE_DECORATOR_NAMES = frozenset(
    {
        "api_view",
        "view_config",
        "require_http_methods",
        "require_GET",
        "require_POST",
        "require_safe",
    }
)

AUTH_DECORATOR_SUBSTRINGS = (
    "login_required",
    "auth_required",
    "token_required",
    "jwt_required",
    "permission_required",
    "staff_member_required",
    "superuser_required",
    "admin_required",
    "user_passes_test",
    "api_login_required",
    "login_required_ajax",
    "requires_auth",
    "require_auth",
    "require_login",
    "requires_login",
    "authenticated",
    "authorize",
    "authorization",
    "permission_classes",
    "authentication_classes",
    "has_permission",
    "check_permission",
    "check_permissions",
    "permissions_required",
    "role_required",
    "roles_required",
    "verified_email_required",
    "basic_auth",
    "http_auth",
    "protect",
    "secure",
    "guard",
    "fresh_jwt_required",
    "jwt_refresh_token_required",
)

AUTHZ_DECORATOR_SUBSTRINGS = (
    "admin",
    "is_admin",
    "permission_required",
    "permission_classes",
    "permissions_required",
    "staff_member_required",
    "staff_required",
    "superuser_required",
    "role_required",
    "roles_required",
    "has_permission",
    "check_permission",
    "check_permissions",
    "user_passes_test",
)

PUBLIC_TOKENS = (
    "health",
    "healthz",
    "healthcheck",
    "readiness",
    "liveness",
    "ping",
    "status",
    "login",
    "signin",
    "logon",
    "signup",
    "register",
    "registration",
    "logout",
    "signout",
    "static",
    "assets",
    "docs",
    "swagger",
    "openapi",
    "redoc",
    "robots",
    "favicon",
    "sitemap",
    "webhook",
    "csrf",
    "index",
    "home",
    "homepage",
    "landing",
    "welcome",
    "about",
    "metrics",
    "forgot_password",
    "oauth",
    "callback",
)

SENSITIVE_TOKENS = (
    "admin",
    "superuser",
    "staff",
    "manage",
    "internal",
    "backend",
    "debug",
    "delete",
    "remove",
    "destroy",
    "drop",
    "purge",
    "truncate",
    "reset",
    "update",
    "edit",
    "modify",
    "create",
    "upload",
    "import",
    "payment",
    "billing",
    "transfer",
    "withdraw",
    "deposit",
    "user/",
    "users",
    "profile",
    "account",
    "password",
    "token",
    "secret",
    "config",
    "settings",
    "credential",
    "private",
    "confidential",
    "flag",
    "start_over",
    "initialize",
    "populate",
)

AUTHZ_SENSITIVE_TOKENS = (
    "admin",
    "secret",
    "confidential",
    "manage",
    "settings",
    "debug",
    "_debug",
    "all-users",
    "all_users",
    "createdb",
    "populate_db",
    "dashboard",
    "internal",
    "private",
    "profile",
    "comments-log",
    "comments_log",
    "reset_password",
)

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

DANGEROUS_SINK_NAMES = {
    "eval",
    "exec",
    "compile",
    "system",
    "popen",
    "render_template_string",
}

DANGEROUS_SINK_CHAINS = {
    ("os", "system"),
    ("os", "popen"),
    ("subprocess", "call"),
    ("subprocess", "run"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "Popen"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
}

DB_WRITE_ATTRS = {
    "save",
    "delete",
    "destroy",
    "remove",
    "update",
    "create",
    "create_all",
    "drop_all",
    "drop",
    "truncate",
    "add",
    "add_all",
    "merge",
    "flush",
    "commit",
    "insert",
    "upsert",
    "execute",
    "executescript",
}

INLINE_AUTH_CALL_NAMES = {
    "authenticate",
    "check_password",
    "verify_password",
    "check_password_hash",
    "login_user",
    "get_jwt_identity",
    "verify_jwt_in_request",
    "get_current_user",
    "decode_token",
    "verify_token",
    "check_auth",
    "require_auth",
    "require_login",
}

INLINE_AUTH_ATTR_TAILS = {
    "is_authenticated",
    "is_active",
    "is_admin",
    "is_staff",
    "is_superuser",
    "check_password",
    "verify_password",
    "check_password_hash",
    "get_jwt_identity",
    "verify_jwt_in_request",
    "current_user",
}

INLINE_AUTH_HEADER_KEYS = (
    "authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "auth-token",
    "x-access-token",
    "token",
    "cookie",
)

GRAPHQL_RESOLVER_PREFIX = "resolve_"

TORNADO_VERB_METHODS = frozenset({"post", "put", "patch", "delete"})
CBV_HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "head", "options"})

HANDLER_CLASS_BASE_TAILS = (
    "RequestHandler",
    "APIView",
    "ViewSet",
    "GenericAPIView",
    "View",
    "Resource",
    "MethodView",
    "ObjectType",
    "Mutation",
    "Query",
    "Subscription",
)

INLINE_AUTH_GRAPHQL_RE = re.compile(
    r"info\s*\.\s*context\s*\.\s*(?:user|request\s*\.\s*user|session)"
    r"|info\s*\[\s*['\"](?:user|session)['\"]\s*\]"
)
INLINE_AUTH_TORNADO_RE = re.compile(r"self\s*\.\s*current_user|self\s*\.\s*get_current_user\s*\(")

PY2_PRINT_RE = re.compile(r"^(\s*)print\s+[^(].*$", re.M)


# Rule 2 — anchored commented-auth-decorator vocabulary, no `auth` broad-match.
COMMENTED_AUTH_DECORATOR_RE = re.compile(
    r"^\s*#\s*@(?:login_required|jwt_required|token_required|admin_required"
    r"|permission_required|requires_auth|api_view|permission_classes)\b"
)


def is_authz_sensitive(url: str | None, function_name: str) -> bool:
    """Return True if the URL or function name looks authorization-sensitive."""
    blob = f"{url or ''} {function_name or ''}".lower()
    return any(tok.lower() in blob for tok in AUTHZ_SENSITIVE_TOKENS)


def has_authz_decorator(decorator_text: str) -> bool:
    """Return True if the decorator text contains an authorization decorator."""
    if not decorator_text:
        return False
    txt = decorator_text.lower()
    return any(sub in txt for sub in AUTHZ_DECORATOR_SUBSTRINGS)


# ---------------------------------------------------------------------------
# AST helpers.
# ---------------------------------------------------------------------------


def _attr_chain(node: ast.AST) -> tuple[str, ...]:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return tuple(reversed(parts))


def _dec_target(dec: ast.AST) -> ast.AST:
    return dec.func if isinstance(dec, ast.Call) else dec


def _dec_text(dec: ast.AST) -> str:
    chain = _attr_chain(_dec_target(dec))
    return ".".join(chain).lower()


def _dec_tail(dec: ast.AST) -> str | None:
    chain = _attr_chain(_dec_target(dec))
    return chain[-1] if chain else None


def _is_route_decorator(dec: ast.AST) -> tuple[bool, str | None, set[str]]:
    methods: set[str] = set()
    url: str | None = None
    tail = _dec_tail(dec)
    if tail is None:
        return False, None, methods
    is_route = False
    chain = _attr_chain(_dec_target(dec))
    if tail in ROUTE_DECORATOR_ATTRS and len(chain) >= 2:
        is_route = True
    elif tail in ROUTE_DECORATOR_NAMES:
        is_route = True
    elif tail == "require_http_methods":
        is_route = True
    if not is_route:
        return False, None, methods

    if tail in {"get", "post", "put", "delete", "patch", "head", "options"}:
        methods.add(tail.upper())

    if isinstance(dec, ast.Call):
        if (
            dec.args
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
        ):
            url = dec.args[0].value
        for kw in dec.keywords:
            if kw.arg in ("methods", "http_method_names"):
                v = kw.value
                if isinstance(v, (ast.List, ast.Tuple, ast.Set)):
                    for elt in v.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            methods.add(elt.value.upper())
            if kw.arg in ("url_path", "path", "url"):
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    url = kw.value.value
        for arg in dec.args[1:]:
            if isinstance(arg, (ast.List, ast.Tuple, ast.Set)):
                for elt in arg.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        mv = elt.value.upper()
                        if mv in {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}:
                            methods.add(mv)
    return True, url, methods


def _is_auth_decorator(dec: ast.AST) -> bool:
    text = _dec_text(dec)
    if not text:
        return False
    return any(sub in text for sub in AUTH_DECORATOR_SUBSTRINGS)


def _has_csrf_exempt(dec: ast.AST) -> bool:
    return _dec_text(dec).endswith("csrf_exempt") or _dec_text(dec) == "csrf_exempt"


def _class_is_handler(cls: ast.ClassDef) -> str | None:
    for b in cls.bases:
        chain = _attr_chain(b)
        if not chain:
            continue
        tail = chain[-1]
        if tail.endswith("RequestHandler"):
            return "tornado"
        if tail.endswith(("APIView", "ViewSet", "GenericAPIView", "MethodView", "Resource")):
            return "drf_or_django"
        if tail.endswith("View"):
            return "django_cbv"
        if tail.endswith(("ObjectType", "Mutation", "Query", "Subscription")):
            return "graphene"
    for item in cls.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if item.name in CBV_HTTP_METHODS:
                return "cbv_method_class"
    return None


def _class_has_permission_classes(cls: ast.ClassDef) -> bool:
    for stmt in cls.body:
        if isinstance(stmt, ast.Assign):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name) and tgt.id in (
                    "permission_classes",
                    "authentication_classes",
                ):
                    if isinstance(stmt.value, (ast.List, ast.Tuple)) and stmt.value.elts:
                        return True
                    if isinstance(stmt.value, ast.Name):
                        return True
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            if stmt.target.id in ("permission_classes", "authentication_classes"):
                return True
    return False


def _function_has_inline_auth(fn: ast.AST) -> bool:
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Name) and f.id in INLINE_AUTH_CALL_NAMES:
                return True
            if isinstance(f, ast.Attribute) and f.attr in INLINE_AUTH_CALL_NAMES:
                return True
        if isinstance(sub, ast.Attribute):
            if sub.attr in INLINE_AUTH_ATTR_TAILS:
                return True
        if isinstance(sub, ast.Subscript):
            slice_node = sub.slice
            if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
                if slice_node.value.lower() in INLINE_AUTH_HEADER_KEYS:
                    base = sub.value
                    chain = _attr_chain(base)
                    if chain and any(t in {"headers", "cookies", "META", "session"} for t in chain):
                        return True
    return False


def _body_has_dangerous_sink(fn: ast.AST) -> tuple[bool, str]:
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Name) and f.id in DANGEROUS_SINK_NAMES:
                return True, f"call:{f.id}"
            if isinstance(f, ast.Attribute):
                chain = _attr_chain(f)
                if len(chain) >= 2 and (chain[0], chain[-1]) in DANGEROUS_SINK_CHAINS:
                    return True, f"chain:{chain[0]}.{chain[-1]}"
                if f.attr == "render_template_string":
                    return True, "attr:render_template_string"
                if (
                    chain
                    and chain[0] == "subprocess"
                    and chain[-1] in {"run", "Popen", "call", "check_call", "check_output"}
                ):
                    for kw in sub.keywords:
                        if (
                            kw.arg == "shell"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value is True
                        ):
                            return True, f"shell:{chain[-1]}"
    return False, ""


def _body_has_state_change(fn: ast.AST) -> tuple[bool, str]:
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Attribute):
                chain = _attr_chain(f)
                if chain and chain[0].lower() in {
                    "request",
                    "response",
                    "resp",
                    "form",
                    "url",
                    "flash",
                }:
                    continue
                if f.attr in DB_WRITE_ATTRS:
                    return True, f"db:{f.attr}"
    return False, ""


def _body_text_lines(src: str, fn: ast.AST, max_lines: int = 30) -> str:
    lines = src.splitlines()
    start = max(0, getattr(fn, "lineno", 1) - 1)
    end = min(len(lines), getattr(fn, "end_lineno", start + max_lines) or (start + max_lines))
    if end - start > max_lines:
        end = start + max_lines
    return "\n".join(lines[start:end])


def _decorator_block_text(src: str, fn: FuncDef) -> str:
    if not getattr(fn, "decorator_list", None):
        return ""
    lines = src.splitlines()
    first = min((getattr(d, "lineno", fn.lineno) for d in fn.decorator_list), default=fn.lineno) - 1
    last = fn.lineno - 1
    if first < 0 or last < 0 or first > last:
        return ""
    return "\n".join(lines[first:last])


def _module_has_before_request_middleware(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                tail = _dec_tail(dec)
                if tail in {"before_request", "before_app_request", "before_first_request"}:
                    return True
    return False


def _name_or_url_has_token(name: str, url: str | None, tokens: tuple[str, ...]) -> bool:
    blob = (name + " " + (url or "")).lower()
    return any(tok in blob for tok in tokens)


def _rewrite_py2_prints(src: str) -> str:
    return PY2_PRINT_RE.sub(lambda m: m.group(1) + "pass", src)


# ---------------------------------------------------------------------------
# Rule 2 — commented-decorator regex pre-pass (anchored vocabulary).
# ---------------------------------------------------------------------------


def _commented_auth_def_lines(src: str) -> set[int]:
    """Return def-line numbers (1-indexed) that follow a commented auth-decorator.

    "Immediately" means within the next ≤ 2 NON-BLANK lines (additional commented
    decorators do not count toward the 2). Intervening def/class breaks the pairing.
    """
    lines = src.splitlines()
    flagged: set[int] = set()
    for idx, line in enumerate(lines):
        if not COMMENTED_AUTH_DECORATOR_RE.match(line):
            continue
        non_blank_seen = 0
        j = idx + 1
        while j < len(lines):
            stripped = lines[j].strip()
            if not stripped:
                j += 1
                continue
            # def line — pair them.
            if re.match(r"^\s*(?:async\s+)?def\s+", lines[j]):
                flagged.add(j + 1)  # 1-indexed
                break
            # class line — break pairing (do NOT flag).
            if re.match(r"^\s*class\s+", lines[j]):
                break
            # additional commented decorator chains — keep walking, no count.
            if stripped.startswith("#"):
                j += 1
                continue
            non_blank_seen += 1
            if non_blank_seen >= 2:
                break
            j += 1
    return flagged


# ---------------------------------------------------------------------------
# Per-file h6 candidate enumeration.
# ---------------------------------------------------------------------------


@dataclass
class Candidate:
    """A candidate endpoint/handler discovered during recon enumeration."""

    file_rel: str
    line: int
    end_line: int
    name: str
    decorator_text: str
    body_text: str
    url: str | None
    methods: set[str]
    handler_kind: str
    class_kind: str | None
    class_name: str | None
    class_has_perms: bool
    has_csrf_exempt: bool
    body_dangerous: bool
    body_dangerous_label: str
    body_state: bool
    body_state_label: str
    inline_auth_present: bool
    decorator_auth_present: bool
    decorator_authz_present: bool
    public_by_token: bool
    sensitive_by_token: bool
    authz_sensitive: bool
    module_has_before_request: bool
    module_imports_text: str
    has_commented_auth_decorator: bool = False
    # Volume-audit telemetry — which Phase-1 branch produced this candidate.
    branch_origin: str = "h6_existing"


def _enumerate_candidates(
    py_file: Path, src: str, repo_root: Path, commented_def_lines: set[int] | None = None
) -> list[Candidate]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        try:
            tree = ast.parse(_rewrite_py2_prints(src))
        except SyntaxError:
            return []

    try:
        rel = py_file.resolve().relative_to(repo_root.resolve())
        rel_posix = str(rel).replace("\\", "/")
    except ValueError:
        rel_posix = str(py_file).replace("\\", "/")

    module_before_request = _module_has_before_request_middleware(tree)

    module_imports_chunks: list[str] = []
    src_lines = src.splitlines()
    for stmt in tree.body[:60]:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            try:
                module_imports_chunks.append(ast.unparse(stmt))
            except Exception:
                pass
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in stmt.decorator_list:
                if _dec_tail(d) in {
                    "before_request",
                    "before_app_request",
                    "before_first_request",
                }:
                    line = getattr(stmt, "lineno", 1) - 1
                    end = min(len(src_lines), line + 6)
                    module_imports_chunks.append("\n".join(src_lines[line:end]))
                    break
    module_imports_text = "\n".join(module_imports_chunks)[:1500]

    parent_class: dict[int, ast.ClassDef] = {}
    class_kinds: dict[int, str | None] = {}
    class_perms: dict[int, bool] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            kind = _class_is_handler(node)
            class_kinds[id(node)] = kind
            class_perms[id(node)] = _class_has_permission_classes(node)
            for sub in ast.walk(node):
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    parent_class[id(sub)] = node

    out: list[Candidate] = []
    commented_def_lines = commented_def_lines or set()

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        fn = node
        cls = parent_class.get(id(fn))
        cls_kind = class_kinds.get(id(cls)) if cls is not None else None
        cls_has_perms = class_perms.get(id(cls), False) if cls is not None else False

        decorator_auth_present = any(_is_auth_decorator(d) for d in fn.decorator_list)
        has_csrf_exempt = any(_has_csrf_exempt(d) for d in fn.decorator_list)

        handler_kind: str | None = None
        url: str | None = None
        methods: set[str] = set()
        for d in fn.decorator_list:
            is_route, u, m = _is_route_decorator(d)
            if is_route:
                handler_kind = "route"
                if u and not url:
                    url = u
                methods.update(m)
        if handler_kind is None:
            if fn.name.startswith(GRAPHQL_RESOLVER_PREFIX):
                args = fn.args.args
                if len(args) >= 2:
                    handler_kind = "graphql"
                elif len(args) == 1:
                    handler_kind = "graphql"
            elif cls_kind == "tornado" and fn.name in TORNADO_VERB_METHODS:
                handler_kind = "tornado"
                methods.add(fn.name.upper())
            elif (
                cls_kind in {"drf_or_django", "django_cbv", "cbv_method_class"}
                and fn.name in CBV_HTTP_METHODS
            ):
                handler_kind = "cbv"
                methods.add(fn.name.upper())
            else:
                if cls is None:
                    args = fn.args.args
                    if args and args[0].arg in ("request", "req"):
                        if _body_uses_request(fn):
                            handler_kind = "django_view"

        if handler_kind is None:
            continue

        body_dangerous, body_dangerous_label = _body_has_dangerous_sink(fn)
        body_state, body_state_label = _body_has_state_change(fn)
        inline_auth = _function_has_inline_auth(fn)

        public_by_token = _name_or_url_has_token(fn.name, url, PUBLIC_TOKENS)
        sensitive_by_token = _name_or_url_has_token(fn.name, url, SENSITIVE_TOKENS)
        authz_sens = is_authz_sensitive(url, fn.name)

        decorator_text = _decorator_block_text(src, fn)
        body_text = _body_text_lines(src, fn, max_lines=30)
        decorator_authz_present = has_authz_decorator(decorator_text)

        has_commented = fn.lineno in commented_def_lines

        # Branch-origin attribution: commented_decorator branch wins iff the
        # def is flagged AND the existing h6 logic would otherwise have it as
        # certain_safe / would skip — but for telemetry we just record
        # commented_decorator when the flag is set.
        origin = "commented_decorator" if has_commented else "h6_existing"

        cand = Candidate(
            file_rel=rel_posix,
            line=fn.lineno,
            end_line=getattr(fn, "end_lineno", fn.lineno) or fn.lineno,
            name=fn.name,
            decorator_text=decorator_text,
            body_text=body_text,
            url=url,
            methods=methods,
            handler_kind=handler_kind,
            class_kind=cls_kind,
            class_name=cls.name if cls is not None else None,
            class_has_perms=cls_has_perms,
            has_csrf_exempt=has_csrf_exempt,
            body_dangerous=body_dangerous,
            body_dangerous_label=body_dangerous_label,
            body_state=body_state,
            body_state_label=body_state_label,
            inline_auth_present=inline_auth,
            decorator_auth_present=decorator_auth_present,
            decorator_authz_present=decorator_authz_present,
            public_by_token=public_by_token,
            sensitive_by_token=sensitive_by_token,
            authz_sensitive=authz_sens,
            module_has_before_request=module_before_request,
            module_imports_text=module_imports_text,
            has_commented_auth_decorator=has_commented,
            branch_origin=origin,
        )
        out.append(cand)

    return out


DJANGO_VIEW_RESPONSE_NAMES = {
    "render",
    "redirect",
    "JsonResponse",
    "HttpResponse",
    "HttpResponseRedirect",
    "HttpResponseForbidden",
    "HttpResponseNotFound",
    "HttpResponseBadRequest",
    "HttpResponseServerError",
    "TemplateResponse",
    "render_to_response",
}


def _body_uses_request(fn: ast.AST) -> bool:
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Attribute):
            if isinstance(sub.value, ast.Name) and sub.value.id == "request":
                return True
        if isinstance(sub, ast.Name) and sub.id == "request":
            return True
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Name) and f.id in DJANGO_VIEW_RESPONSE_NAMES:
                return True
            if isinstance(f, ast.Attribute) and f.attr in DJANGO_VIEW_RESPONSE_NAMES:
                return True
    return False
