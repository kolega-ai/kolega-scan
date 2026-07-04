"""Offline unit tests for the recon AST enumeration (no LLM / no network).

These exercise ``_enumerate_candidates`` (the whole route/decorator/auth/sink
AST pipeline) plus the individual heuristic helpers by feeding source strings
and asserting the emitted candidates. Pure functions — deterministic, no key.
"""

import ast
from pathlib import Path

from kolega_security_scanner.scanner import recon_enumerate as re_

REPO = Path("/repo")
APP = REPO / "app.py"


def _cands(src: str):
    return re_._enumerate_candidates(APP, src, REPO)


def _by_name(src: str):
    return {c.name: c for c in _cands(src)}


# --------------------------------------------------------------------------
# _enumerate_candidates — end-to-end AST pipeline
# --------------------------------------------------------------------------


def test_flask_route_sensitive_dangerous_no_auth():
    src = """
import os
from flask import Flask
app = Flask(__name__)

@app.route("/admin/delete", methods=["POST"])
def delete_user():
    os.system("rm -rf " + request.args["path"])
    return "ok"
"""
    c = _by_name(src)["delete_user"]
    assert c.handler_kind == "route"
    assert c.url == "/admin/delete"
    assert "POST" in c.methods
    assert c.body_dangerous is True
    assert c.sensitive_by_token is True
    assert c.decorator_auth_present is False


def test_flask_route_with_login_required_sets_auth():
    src = """
from flask import Flask
from flask_login import login_required
app = Flask(__name__)

@app.route("/dashboard")
@login_required
def dashboard():
    return "secret"
"""
    c = _by_name(src)["dashboard"]
    assert c.decorator_auth_present is True


def test_public_token_route_marked_public():
    src = """
from flask import Flask
app = Flask(__name__)

@app.route("/health")
def health():
    return "ok"
"""
    c = _by_name(src)["health"]
    assert c.public_by_token is True


def test_csrf_exempt_detected():
    src = """
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def webhook(request):
    return request.body
"""
    c = _by_name(src)["webhook"]
    assert c.has_csrf_exempt is True


def test_django_function_view_using_request():
    src = """
from django.shortcuts import render

def profile(request):
    user = request.user
    return render(request, "p.html")
"""
    c = _by_name(src)["profile"]
    assert c.handler_kind == "django_view"


def test_drf_apiview_with_permission_classes():
    src = """
from rest_framework.views import APIView
from rest_framework.permissions import IsAdminUser

class AdminView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        return request.user
"""
    c = _by_name(src)["get"]
    assert c.handler_kind == "cbv"
    assert c.class_has_perms is True
    assert c.class_name == "AdminView"


def test_tornado_handler_verb_method():
    src = """
import tornado.web

class MainHandler(tornado.web.RequestHandler):
    def post(self):
        self.write("x")
"""
    c = _by_name(src)["post"]
    assert c.handler_kind == "tornado"
    assert "POST" in c.methods


def test_graphql_resolver():
    src = """
def resolve_users(root, info):
    return info.context
"""
    c = _by_name(src)["resolve_users"]
    assert c.handler_kind == "graphql"


def test_inline_auth_detected():
    src = """
from flask import Flask
app = Flask(__name__)

@app.route("/me")
def me():
    if not current_user.is_authenticated:
        return "no"
    return "yes"
"""
    c = _by_name(src)["me"]
    assert c.inline_auth_present is True


def test_state_change_body():
    src = """
from flask import Flask
app = Flask(__name__)

@app.route("/save", methods=["POST"])
def save():
    db.session.commit()
    return "ok"
"""
    c = _by_name(src)["save"]
    assert c.body_state is True


def test_non_handler_function_not_a_candidate():
    src = """
def helper(a, b):
    return a + b
"""
    assert _cands(src) == []


def test_syntax_error_returns_empty():
    assert re_._enumerate_candidates(APP, "def broken(:\n", REPO) == []


def test_python2_print_is_recovered():
    # py2 print statement is a SyntaxError under py3; the rewriter recovers it.
    src = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        '@app.route("/x")\n'
        "def x():\n"
        '    print "hi"\n'
    )
    names = _by_name(src)
    assert "x" in names


def test_commented_auth_decorator_flag():
    src = """
from flask import Flask
app = Flask(__name__)

# @login_required
@app.route("/admin")
def admin_panel():
    return "x"
"""
    commented = re_._commented_auth_def_lines(src)
    cands = re_._enumerate_candidates(APP, src, REPO, commented_def_lines=commented)
    c = {x.name: x for x in cands}["admin_panel"]
    assert c.has_commented_auth_decorator is True
    assert c.branch_origin == "commented_decorator"


# --------------------------------------------------------------------------
# Heuristic helpers — direct unit tests
# --------------------------------------------------------------------------


def test_is_authz_sensitive():
    assert re_.is_authz_sensitive("/admin/users", "list_users") is True
    assert re_.is_authz_sensitive("/about", "about_page") is False


def test_has_authz_decorator():
    assert re_.has_authz_decorator("@permission_required('admin')") is True
    assert re_.has_authz_decorator("@app.route('/x')") is False


def test_name_or_url_has_token():
    assert re_._name_or_url_has_token("delete_thing", None, re_.SENSITIVE_TOKENS) is True
    assert re_._name_or_url_has_token("index", "/home", re_.SENSITIVE_TOKENS) is False


def test_rewrite_py2_prints_neutralizes_to_parseable():
    # py2 print statements are rewritten to `pass` so the file parses under py3.
    src = 'def f():\n    print "hello"\n'
    out = re_._rewrite_py2_prints(src)
    assert 'print "hello"' not in out
    ast.parse(out)  # must now be valid py3


def _first_func(src: str) -> ast.AST:
    return next(
        n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
    )


def test_body_has_dangerous_sink_variants():
    assert re_._body_has_dangerous_sink(_first_func("def f():\n eval(x)\n"))[0] is True
    assert re_._body_has_dangerous_sink(_first_func("def f():\n subprocess.call(x)\n"))[0] is True
    assert re_._body_has_dangerous_sink(_first_func("def f():\n return 1\n"))[0] is False


def test_is_route_decorator_methods_parsed():
    dec = (
        ast.parse('@app.route("/x", methods=["GET", "POST"])\ndef v(): ...')
        .body[0]
        .decorator_list[0]
    )
    is_route, url, methods = re_._is_route_decorator(dec)
    assert is_route is True
    assert url == "/x"
    assert methods == {"GET", "POST"}


def test_is_auth_decorator():
    dec = ast.parse("@login_required\ndef v(): ...").body[0].decorator_list[0]
    assert re_._is_auth_decorator(dec) is True
    dec2 = ast.parse("@staticmethod\ndef v(): ...").body[0].decorator_list[0]
    assert re_._is_auth_decorator(dec2) is False


def test_class_is_handler_kinds():
    drf = ast.parse("class V(APIView):\n def get(self): ...").body[0]
    assert re_._class_is_handler(drf) is not None
    plain = ast.parse("class C:\n x = 1").body[0]
    assert re_._class_is_handler(plain) is None
