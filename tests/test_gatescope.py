#!/usr/bin/env python3
"""Tests for gatescope: route extraction, guard resolution, every rule, the matrix.

Run: python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import audit  # noqa: E402
import render  # noqa: E402
import routes  # noqa: E402

EXAMPLES = os.path.join(ROOT, "examples", "project-api")


def tree(files: dict) -> str:
    root = tempfile.mkdtemp(prefix="gatescope-test-")
    for rel, body in files.items():
        full = os.path.join(root, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(body)
    return root


class Base(unittest.TestCase):
    def setUp(self):
        self._dirs = []

    def tearDown(self):
        for d in self._dirs:
            shutil.rmtree(d, ignore_errors=True)

    def build(self, files: dict) -> dict:
        root = tree(files)
        self._dirs.append(root)
        return routes.build(root)

    def one(self, files: dict) -> dict:
        doc = self.build(files)
        self.assertEqual(doc["route_count"], 1, doc["routes"])
        return doc["routes"][0]

    def by_label(self, files: dict) -> dict:
        doc = self.build(files)
        return {f"{r['method']} {r['path']}": r for r in doc["routes"]}

    def rules(self, files: dict) -> set:
        doc = self.build(files)
        return {f["rule"] for f in audit.audit(doc)["findings"]}


# --------------------------------------------------------------------------
# route discovery
# --------------------------------------------------------------------------

class TestDiscovery(Base):
    def test_express_route_and_inline_guard(self):
        r = self.one({"api.js": "app.get('/health', requireAuth, (req, res) => {});\n"})
        self.assertEqual((r["method"], r["path"]), ("GET", "/health"))
        self.assertEqual(r["level"], "authed")
        self.assertEqual(r["guards"][0]["via"], "inline")

    def test_express_route_with_no_guard_is_public(self):
        r = self.one({"api.js": "app.delete('/thing', (req, res) => {});\n"})
        self.assertEqual(r["level"], "public")
        self.assertTrue(r["mutating"])

    def test_http_client_calls_are_not_routes(self):
        doc = self.build({"client.js": "axios.get('/users');\nfetch('/api/x');\n"})
        self.assertEqual(doc["route_count"], 0)

    def test_router_mount_prefix_is_resolved_across_files(self):
        got = self.by_label({
            "src/server.ts": (
                "import projects from './routes/projects';\n"
                "app.use('/api/projects', projects);\n"
            ),
            "src/routes/projects.ts": "router.get('/:id', requireAuth, (req, res) => {});\n",
        })
        self.assertIn("GET /api/projects/:id", got)

    def test_guard_at_the_mount_covers_the_mounted_router(self):
        got = self.by_label({
            "src/server.ts": (
                "import admin from './routes/admin';\n"
                "app.use('/api/admin', requireAuth);\n"
                "app.use('/api/admin', admin);\n"
            ),
            "src/routes/admin.ts": "router.get('/users', (req, res) => {});\n",
        })
        r = got["GET /api/admin/users"]
        self.assertEqual(r["level"], "authed")
        self.assertEqual(r["guards"][0]["via"], "mounted-middleware")

    def test_express_mount_does_not_guard_a_next_handler(self):
        got = self.by_label({
            "src/server.ts": "app.use('/api', requireAuth);\n",
            "app/api/billing/route.ts": "export async function GET(request) { return x; }\n",
        })
        self.assertEqual(got["GET /api/billing"]["level"], "public")

    def test_next_route_handler(self):
        got = self.by_label({
            "app/api/projects/[id]/route.ts":
                "export async function DELETE(request) { await db.p.delete(); }\n",
        })
        r = got["DELETE /api/projects/[id]"]
        self.assertEqual(r["kind"], "next-route")
        self.assertEqual(r["params"], ["id"])

    def test_next_route_group_is_not_part_of_the_url(self):
        got = self.by_label({
            "app/(dashboard)/api/me/route.ts": "export async function GET() { return 1; }\n",
        })
        self.assertIn("GET /api/me", got)

    def test_server_action_is_a_post_endpoint(self):
        r = self.one({
            "app/actions.ts": "'use server';\nexport async function wipe() { await db.x.delete(); }\n",
        })
        self.assertEqual(r["kind"], "server-action")
        self.assertEqual(r["method"], "POST")
        self.assertEqual(r["handler"], "wipe")

    def test_fastapi_route_and_depends_guard(self):
        r = self.one({
            "main.py": (
                "@app.get('/items')\n"
                "async def items(user = Depends(get_current_user)):\n"
                "    return []\n"
            ),
        })
        self.assertEqual((r["method"], r["path"]), ("GET", "/items"))
        self.assertEqual(r["level"], "authed")

    def test_flask_route_methods_and_decorator_guard(self):
        got = self.by_label({
            "app.py": (
                "@app.route('/post', methods=['POST'])\n"
                "@login_required\n"
                "def create():\n"
                "    return ''\n"
            ),
        })
        self.assertIn("POST /post", got)
        self.assertEqual(got["POST /post"]["level"], "authed")

    def test_laravel_route_with_middleware_chain(self):
        r = self.one({
            "routes/web.php":
                "<?php\nRoute::post('/orders', [OrderController::class, 'store'])"
                "->middleware('auth');\n",
        })
        self.assertEqual((r["method"], r["path"]), ("POST", "/orders"))
        self.assertEqual(r["level"], "authed")

    def test_laravel_group_prefix_and_role(self):
        got = self.by_label({
            "routes/web.php": (
                "<?php\nRoute::middleware(['auth', 'role:admin'])"
                "->prefix('admin')->group(function () {\n"
                "    Route::get('/users', [A::class, 'index']);\n});\n"
            ),
        })
        r = got["GET /admin/users"]
        self.assertEqual(r["level"], "role")
        self.assertIn("admin", r["roles"])

    def test_named_handler_does_not_borrow_the_next_routes_body(self):
        got = self.by_label({"a.js": (
            "app.put('/p/:id', requireAuth, updateProject);\n"
            "app.delete('/p/:id', requireAuth, async (req, res) => {\n"
            "  await db.project.deleteMany({ where: { id: req.params.id, userId: req.user.id } });\n"
            "});\n"
        )})
        # the PUT's handler is elsewhere: its owner check is unknown, not borrowed
        self.assertEqual(got["PUT /p/:id"]["level"], "authed")
        self.assertEqual(got["DELETE /p/:id"]["level"], "owner")

    def test_named_handler_on_a_wrapped_call(self):
        got = self.by_label({"a.js": (
            "app.put('/p/:id',\n  requireAuth,\n  updateProject);\n"
            "app.delete('/q/:id', requireAuth, async (req, res) => {\n"
            "  await db.p.deleteMany({ where: { id: req.params.id, userId: req.user.id } });\n"
            "});\n"
        )})
        self.assertEqual(got["PUT /p/:id"]["level"], "authed")
        self.assertEqual(got["DELETE /q/:id"]["level"], "owner")

    def test_unscoped_named_handler_is_reported_as_an_idor(self):
        self.assertIn("id_param_no_owner_check", self.rules({"a.js": (
            "app.patch('/p/:id', requireAuth, updateProject);\n"
            "app.delete('/p/:id', requireAuth, async (req, res) => {\n"
            "  await db.project.deleteMany({ where: { id: req.params.id, userId: req.user.id } });\n"
            "});\n"
        )}))

    def test_arrow_handler_without_braces_is_still_read(self):
        r = self.one({"a.js": "app.get('/h', requireAuth, (req, res) =>\n  res.json({ ok: true }));\n"})
        self.assertEqual(r["level"], "authed")

    def test_next_exported_handler_alias_has_no_body_to_borrow(self):
        got = self.by_label({"app/api/x/route.ts": (
            "export const POST = handler;\n"
            "export async function DELETE(req: Request) {\n"
            "  const session = await auth();\n"
            "  if (!session) return new Response('x', { status: 401 });\n"
            "  await db.t.delete({ where: { userId: session.user.id } });\n}\n"
        )})
        self.assertEqual(got["POST /api/x"]["level"], "public")
        self.assertEqual(got["DELETE /api/x"]["level"], "owner")

    def test_laravel_group_ends_at_its_closing_brace(self):
        got = self.by_label({
            "routes/api.php": (
                "<?php\nRoute::middleware(['auth:sanctum'])->group(function () {\n"
                "    Route::get('/projects/{id}', [P::class, 'show']);\n"
                "});\n"
                "Route::post('/webhooks/stripe', [W::class, 'handle']);\n"
            ),
        })
        self.assertEqual(got["GET /projects/{id}"]["level"], "authed")
        # declared after the group closed: crediting the group here hides a hole
        self.assertEqual(got["POST /webhooks/stripe"]["level"], "public")
        self.assertEqual(got["POST /webhooks/stripe"]["guards"], [])

    def test_laravel_nested_groups_close_independently(self):
        got = self.by_label({
            "routes/api.php": (
                "<?php\nRoute::middleware('auth')->prefix('api')->group(function () {\n"
                "    Route::middleware('role:admin')->prefix('admin')->group(function () {\n"
                "        Route::get('/users', [U::class, 'index']);\n"
                "    });\n"
                "    Route::get('/me', [U::class, 'me']);\n"
                "});\n"
            ),
        })
        self.assertEqual(got["GET /api/admin/users"]["level"], "role")
        self.assertEqual(got["GET /api/me"]["level"], "authed")

    def test_laravel_group_declared_over_several_lines(self):
        got = self.by_label({
            "routes/web.php": (
                "<?php\nRoute::middleware(['auth'])\n"
                "    ->prefix('account')\n"
                "    ->group(function () {\n"
                "        Route::get('/settings', [S::class, 'show']);\n"
                "    });\n"
                "Route::get('/pricing', [M::class, 'pricing']);\n"
            ),
        })
        self.assertEqual(got["GET /account/settings"]["level"], "authed")
        self.assertEqual(got["GET /pricing"]["level"], "public")

    def test_laravel_array_style_group(self):
        got = self.by_label({
            "routes/web.php": (
                "<?php\nRoute::group(['middleware' => ['auth'], 'prefix' => 'admin'], function () {\n"
                "    Route::get('/users', [U::class, 'index']);\n"
                "});\n"
            ),
        })
        r = got["GET /admin/users"]
        # the prefix is `admin`; the middleware is only `auth`
        self.assertEqual(r["level"], "authed")
        self.assertEqual(r["roles"], [])

    def test_laravel_prefix_is_not_a_role(self):
        got = self.by_label({
            "routes/web.php": (
                "<?php\nRoute::middleware('auth')->prefix('admin')->group(function () {\n"
                "    Route::get('/users', [U::class, 'index']);\n"
                "});\n"
            ),
        })
        self.assertEqual(got["GET /admin/users"]["level"], "authed")

    def test_laravel_route_name_is_not_a_guard(self):
        r = self.one({
            "routes/web.php":
                "<?php\nRoute::post('/login', [A::class, 'store'])->name('auth.login');\n",
        })
        self.assertEqual(r["level"], "public")

    def test_laravel_web_and_guest_are_not_identity(self):
        got = self.by_label({
            "routes/web.php": (
                "<?php\nRoute::middleware('web')->group(function () {\n"
                "    Route::post('/contact', [C::class, 'send']);\n"
                "});\n"
                "Route::get('/register', [R::class, 'create'])->middleware('guest');\n"
            ),
        })
        self.assertEqual(got["POST /contact"]["level"], "public")
        self.assertEqual(got["GET /register"]["level"], "public")

    def test_laravel_guard_chained_in_front_of_one_route(self):
        got = self.by_label({
            "routes/api.php": (
                "<?php\nRoute::middleware('auth:sanctum')->get('/me', [U::class, 'me']);\n"
                "Route::get('/status', [S::class, 'show']);\n"
            ),
        })
        self.assertEqual(got["GET /me"]["level"], "authed")
        # and it is one route's guard, not a group that never closes
        self.assertEqual(got["GET /status"]["level"], "public")

    def test_laravel_middleware_on_the_line_below_the_route(self):
        r = self.one({
            "routes/api.php": (
                "<?php\nRoute::delete('/projects/{id}', [P::class, 'destroy'])\n"
                "    ->middleware('auth')\n"
                "    ->name('projects.destroy');\n"
            ),
        })
        self.assertEqual(r["level"], "authed")

    def test_laravel_without_middleware_removes_the_inherited_guard(self):
        got = self.by_label({
            "routes/api.php": (
                "<?php\nRoute::middleware('auth')->group(function () {\n"
                "    Route::get('/feed', [F::class, 'index'])->withoutMiddleware('auth');\n"
                "    Route::get('/inbox', [I::class, 'index']);\n"
                "});\n"
            ),
        })
        self.assertEqual(got["GET /feed"]["level"], "public")
        self.assertEqual(got["GET /inbox"]["level"], "authed")

    def test_laravel_resource_expands_to_the_routes_it_registers(self):
        got = self.by_label({
            "routes/api.php":
                "<?php\nRoute::apiResource('photos', PhotoController::class)->middleware('auth');\n",
        })
        self.assertEqual(sorted(got), [
            "DELETE /photos/{photo}", "GET /photos", "GET /photos/{photo}",
            "POST /photos", "PUT /photos/{photo}",
        ])
        self.assertTrue(all(r["level"] == "authed" for r in got.values()))

    def test_laravel_resource_only(self):
        got = self.by_label({
            "routes/api.php":
                "<?php\nRoute::resource('categories', C::class)->only(['index', 'show']);\n",
        })
        self.assertEqual(sorted(got), ["GET /categories", "GET /categories/{category}"])

    def test_laravel_throttle_on_the_group_counts_for_its_routes(self):
        self.assertNotIn("auth_route_no_rate_limit", self.rules({
            "routes/api.php": (
                "<?php\nRoute::middleware('throttle:5,1')->group(function () {\n"
                "    Route::post('/login', [A::class, 'store']);\n"
                "});\n"
            ),
        }))

    def test_router_route_chain_lists_every_verb(self):
        got = self.by_label({"a.js": (
            "router.route('/items')\n  .get(requireAuth, list)\n  .post(requireAuth, create);\n")})
        self.assertEqual(sorted(got), ["GET /items", "POST /items"])
        self.assertTrue(all(r["level"] == "authed" for r in got.values()))

    def test_an_unguarded_verb_in_a_chain_is_reported(self):
        files = {"a.js": (
            "router.route('/items')\n  .get(list)\n  .post(requireAuth, create)\n  .delete(remove);\n")}
        got = self.by_label(files)
        self.assertEqual(got["POST /items"]["level"], "authed")
        self.assertEqual(got["DELETE /items"]["level"], "public")
        self.assertIn("unauthenticated_mutation", self.rules(files))

    def test_router_route_chain_on_one_line(self):
        got = self.by_label({"a.js": (
            "router.route('/a').get(requireAuth, list).post(requireAuth, create);\n")})
        self.assertEqual(sorted(got), ["GET /a", "POST /a"])

    def test_router_route_chain_with_multi_line_inline_handlers(self):
        got = self.by_label({"a.js": (
            "router.route('/p/:id')\n"
            "  .get(requireAuth, async (req, res) => {\n"
            "    res.json(await db.p.findFirst({ where: { id: req.params.id, userId: req.user.id } }));\n"
            "  })\n"
            "  .delete(async (req, res) => {\n"
            "    await db.p.delete({ where: { id: req.params.id } });\n"
            "  });\n")})
        self.assertEqual(got["GET /p/:id"]["level"], "owner")
        self.assertEqual(got["DELETE /p/:id"]["level"], "public")

    def test_router_route_chain_gets_the_mount_prefix_and_mount_guard(self):
        got = self.by_label({
            "server.js": ("const items = require('./items');\n"
                          "app.use('/api/items', requireAuth);\napp.use('/api/items', items);\n"),
            "items.js": "router.route('/').post(create);\n",
        })
        self.assertEqual(got["POST /api/items"]["level"], "authed")

    def test_a_route_after_a_chain_is_still_found(self):
        got = self.by_label({"a.js": (
            "router.route('/a').get(list).post(create);\nrouter.get('/b', requireAuth, other);\n")})
        self.assertEqual(sorted(got), ["GET /a", "GET /b", "POST /a"])

    def test_a_http_client_route_call_is_not_a_router(self):
        self.assertEqual(self.build({"a.js": "supertest.route('/x').get(y);\n"})["route_count"], 0)

    def test_fastapi_router_prefix_and_dependencies(self):
        got = self.by_label({"m.py": (
            "from fastapi import APIRouter, Depends\n"
            "router = APIRouter(prefix='/items', dependencies=[Depends(get_current_user)])\n\n"
            "@router.post('/')\ndef create(payload: dict):\n    db.add(payload)\n\n"
            "@router.get('/{item_id}')\ndef read(item_id: int):\n    return 1\n")})
        self.assertEqual(got["POST /items"]["level"], "authed")
        self.assertEqual(got["GET /items/{item_id}"]["level"], "authed")

    def test_fastapi_empty_route_path_under_a_prefix(self):
        got = self.by_label({"m.py": (
            "router = APIRouter(prefix='/items')\n\n@router.get('')\ndef lst():\n    return 1\n")})
        self.assertIn("GET /items", got)

    def test_fastapi_include_router_across_files(self):
        got = self.by_label({
            "app/main.py": ("from fastapi import FastAPI, Depends\nfrom app.routers import items\n"
                            "app = FastAPI()\n"
                            "app.include_router(items.router, prefix='/api', "
                            "dependencies=[Depends(verify_token)])\n"),
            "app/routers/items.py": ("from fastapi import APIRouter\nrouter = APIRouter(prefix='/items')\n\n"
                                     "@router.delete('/{i}')\ndef rm(i: int):\n    db.delete(i)\n"),
        })
        self.assertEqual(got["DELETE /api/items/{i}"]["level"], "authed")

    def test_fastapi_include_router_through_an_aliased_import(self):
        got = self.by_label({
            "app/main.py": ("from app.routers.items import router as items_router\n"
                            "app = FastAPI()\napp.include_router(items_router, prefix='/v1')\n"),
            "app/routers/items.py": "router = APIRouter()\n\n@router.get('/x')\ndef x():\n    return 1\n",
        })
        self.assertIn("GET /v1/x", got)

    def test_fastapi_app_level_dependencies(self):
        r = self.one({"m.py": (
            "app = FastAPI(dependencies=[Depends(verify_token)])\n\n"
            "@app.post('/x')\ndef x():\n    db.add(1)\n")})
        self.assertEqual(r["level"], "authed")

    def test_fastapi_nested_routers_chain_their_prefixes_and_guards(self):
        r = self.one({"m.py": (
            "api = APIRouter(prefix='/api', dependencies=[Depends(get_current_user)])\n"
            "items = APIRouter(prefix='/items')\napi.include_router(items)\n"
            "app = FastAPI()\napp.include_router(api)\n\n"
            "@items.post('/')\ndef c():\n    db.add(1)\n")})
        self.assertEqual((r["path"], r["level"]), ("/api/items", "authed"))

    def test_flask_blueprint_prefix_makes_an_admin_path_visible(self):
        files = {"m.py": (
            "bp = Blueprint('admin', __name__, url_prefix='/admin')\n\n"
            "@bp.route('/users', methods=['POST'])\n@login_required\ndef add():\n    db.add(1)\n")}
        self.assertEqual(self.one(files)["path"], "/admin/users")
        self.assertIn("admin_path_without_role_guard", self.rules(files))

    def test_flask_register_blueprint_prefix_wins(self):
        got = self.by_label({
            "app.py": ("from admin import bp\napp = Flask(__name__)\n"
                       "app.register_blueprint(bp, url_prefix='/staff')\n"),
            "admin.py": ("bp = Blueprint('admin', __name__, url_prefix='/admin')\n\n"
                         "@bp.route('/users')\ndef u():\n    return 1\n"),
        })
        self.assertIn("GET /staff/users", got)

    def test_routers_with_the_same_name_in_different_files_are_not_mixed(self):
        got = self.by_label({
            "a.py": ("router = APIRouter(prefix='/a', dependencies=[Depends(get_current_user)])\n\n"
                     "@router.post('/x')\ndef x():\n    db.add(1)\n"),
            "b.py": "router = APIRouter(prefix='/b')\n\n@router.post('/y')\ndef y():\n    db.add(1)\n",
        })
        self.assertEqual(got["POST /a/x"]["level"], "authed")
        self.assertEqual(got["POST /b/y"]["level"], "public")

    def test_double_slash_inside_a_template_literal_does_not_hide_the_rest_of_the_line(self):
        r = self.one({"a.js": (
            "app.patch('/p/:id', requireAuth, async (req, res) => {\n"
            "  await db.p.updateMany({ data: { url: `https://x.com/${req.params.id}`, userId: req.user.id },"
            " where: { id: req.params.id, userId: req.user.id } });\n});\n")})
        self.assertEqual(r["level"], "owner")

    def test_code_after_a_private_member_is_not_a_comment(self):
        r = self.one({"a.js": (
            "app.patch('/p/:id', requireAuth, async (req, res) => {\n"
            "  const x = this.#cache; await db.p.updateMany({ where: { id: req.params.id, userId: req.user.id } });\n"
            "});\n")})
        self.assertEqual(r["level"], "owner")

    def test_real_comments_are_still_ignored(self):
        got = self.by_label({"a.js": "// app.post('/old', h);\napp.get('/ok', requireAuth, h); // trailing\n"})
        self.assertEqual(sorted(got), ["GET /ok"])
        py = self.by_label({"m.py": "# @app.post('/old')\n@app.get('/ok')\ndef ok():\n    return 1  # fine\n"})
        self.assertEqual(sorted(py), ["GET /ok"])

    def test_comment_is_not_a_route(self):
        doc = self.build({"api.js": "// app.get('/old', handler);\n"})
        self.assertEqual(doc["route_count"], 0)


# --------------------------------------------------------------------------
# guard resolution
# --------------------------------------------------------------------------

class TestGuards(Base):
    def test_common_guard_names_are_recognised(self):
        for name in ("auth", "isLoggedIn", "ensureAuthenticated", "ensureAuth", "isAuth",
                     "verifyUser", "checkJwt", "jwtAuth", "requireUser", "validateToken",
                     "requireLogin", "is_logged_in", "ensure_logged_in", "authenticateUser"):
            with self.subTest(name):
                r = self.one({"api.js": f"app.post('/x', {name}, async (req, res) => {{ await db.t.create({{}}); }});\n"})
                self.assertEqual(r["level"], "authed")

    def test_names_that_merely_contain_auth_are_not_guards(self):
        for name in ("authController.register", "auth.login", "authService.create",
                     "validateBody(schema)", "author", "oauthCallback", "unauthorized",
                     "setAuthCookie"):
            with self.subTest(name):
                r = self.one({"api.js": f"app.post('/x', {name}, async (req, res) => {{ await db.t.create({{}}); }});\n"})
                self.assertEqual(r["level"], "public")

    def test_a_guard_name_in_a_handler_body_is_not_a_guard(self):
        r = self.one({"api.js": (
            "app.post('/x', async (req, res) => {\n"
            "  const auth = require('./auth');\n  await db.t.create({});\n});\n")})
        self.assertEqual(r["level"], "public")

    def test_fastapi_get_current_active_user_is_a_guard(self):
        r = self.one({"m.py": "@router.post('/x')\ndef f(user=Depends(get_current_active_user)):\n    db.add(1)\n"})
        self.assertEqual(r["level"], "authed")

    def test_a_guarded_api_with_camelcase_guards_has_no_critical(self):
        rules = self.rules({"api.js": (
            "app.post('/a', ensureAuthenticated, h);\napp.delete('/a/b', isLoggedIn, h);\n")})
        self.assertNotIn("unauthenticated_mutation", rules)
        self.assertNotIn("no_identity_guard_anywhere", rules)

    def test_optional_session_and_a_validation_throw_is_not_a_guard(self):
        r = self.one({"api.js": (
            "app.post('/comments', async (req, res) => {\n"
            "  const who = req.user ? req.user.name : 'anon';\n"
            "  if (!req.body.text) throw new Error('text required');\n"
            "  await db.comment.create({ data: { text: req.body.text, who } });\n});\n")})
        self.assertEqual(r["level"], "public")

    def test_a_negated_request_field_is_not_an_identity_check(self):
        r = self.one({"api.js": (
            "app.post('/c', async (req, res) => {\n  const s = req.user;\n"
            "  if (!req.body.user) throw new Error('bad');\n  await db.c.create({});\n});\n")})
        self.assertEqual(r["level"], "public")

    def test_a_throw_after_a_negative_identity_check_is_enforcement(self):
        for name, files in {
            "401": {"a.js": "app.post('/c', async (req, res) => {\n"
                    "  const session = await getSession(req);\n"
                    "  if (!session) return res.status(401).end();\n  await db.c.create({});\n});\n"},
            "redirect": {"app/x/actions.ts": "'use server';\nexport async function a() {\n"
                         "  const session = await auth();\n  if (!session) redirect('/login');\n"
                         "  await db.t.create({});\n}\n"},
            "throw": {"app/x/actions.ts": "'use server';\nexport async function a() {\n"
                      "  const session = await auth();\n  if (!session?.user) throw new Error('nope');\n"
                      "  await db.t.create({});\n}\n"},
            "python is None": {"m.py": "@app.post('/x')\ndef f(request):\n    user = request.user\n"
                               "    if user is None:\n        raise HTTPException(status_code=400)\n    db.add(1)\n"},
            "python not current_user": {"m.py": "@app.route('/x', methods=['POST'])\ndef f():\n"
                                        "    if not current_user:\n        abort(400)\n    db.add(1)\n"},
        }.items():
            with self.subTest(name):
                self.assertEqual(self.one(files)["level"], "authed")

    def test_a_session_looked_up_and_never_acted_on_guards_nothing(self):
        r = self.one({"api.js": (
            "app.post('/c', async (req, res) => {\n  const session = await getSession(req);\n"
            "  log(session);\n  await db.c.create({});\n});\n")})
        self.assertEqual(r["level"], "public")

    def test_a_role_check_in_the_body_counts_only_when_it_denies(self):
        denies = self.one({"api.js": (
            "app.post('/c', requireAuth, async (req, res) => {\n"
            "  if (!isAdmin(req.user)) throw new Error('no');\n  await db.c.create({});\n});\n")})
        self.assertEqual(denies["level"], "role")
        ignored = self.one({"api.js": (
            "app.post('/c', requireAuth, async (req, res) => {\n"
            "  const ok = isAdmin(req.user);\n  await db.c.create({});\n});\n")})
        self.assertEqual(ignored["level"], "authed")

    def test_guards_on_a_wrapped_route_call_are_route_guards(self):
        for name, (src, want) in {
            "named handler": ("app.put('/p/:id',\n  requireAuth,\n  updateProject);\n", "authed"),
            "inline handler on its own line": ("app.post('/p',\n  requireAuth,\n  async (req, res) => {\n"
                                               "    await db.p.create({});\n  });\n", "authed"),
            "role chain": ("app.post('/p',\n  requireAuth,\n  requireRole('admin'),\n  async (req, res) => {\n"
                           "    await db.p.create({});\n  });\n", "role"),
            "a guard-looking name inside the handler": ("app.post('/p',\n  async (req, res) => {\n"
                                                        "    const requireAuth = 1;\n    await db.p.create({});\n  });\n", "public"),
        }.items():
            with self.subTest(name):
                self.assertEqual(self.one({"api.js": src})["level"], want)

    def test_role_guard_beats_identity_guard(self):
        r = self.one({
            "api.js": "app.get('/x', requireAuth, requireRole('admin'), h);\n",
        })
        self.assertEqual(r["level"], "role")
        self.assertEqual(r["roles"], ["admin"])

    def test_ownership_via_session_id_in_where(self):
        r = self.one({
            "api.js": (
                "app.get('/mine', requireAuth, async (req, res) => {\n"
                "  const rows = await db.p.findMany({ where: { userId: req.user.id } });\n"
                "});\n"
            ),
        })
        self.assertTrue(r["owner_check"])
        self.assertEqual(r["level"], "owner")

    def test_caller_supplied_id_is_not_ownership(self):
        r = self.one({
            "api.js": (
                "app.get('/u/:id', requireAuth, async (req, res) => {\n"
                "  const row = await db.u.findUnique({ where: { id: req.params.id } });\n"
                "});\n"
            ),
        })
        self.assertFalse(r["owner_check"])
        self.assertEqual(r["level"], "authed")

    def test_session_read_and_enforced_inside_handler_counts(self):
        r = self.one({
            "app/api/me/route.ts": (
                "export async function GET() {\n"
                "  const session = await auth();\n"
                "  if (!session?.user) return new Response(null, { status: 401 });\n"
                "  return Response.json({});\n"
                "}\n"
            ),
        })
        self.assertTrue(r["session_source"])
        self.assertTrue(r["enforces"])
        self.assertEqual(r["level"], "authed")

    def test_session_read_and_ignored_does_not_count(self):
        r = self.one({
            "app/api/me/route.ts": (
                "export async function GET() {\n"
                "  const session = await auth();\n"
                "  const rows = await db.invoice.findMany();\n"
                "  return Response.json(rows);\n"
                "}\n"
            ),
        })
        self.assertTrue(r["session_source"])
        self.assertFalse(r["enforces"])
        self.assertEqual(r["level"], "public")

    def test_camelcase_rate_limiter_is_recognised(self):
        r = self.one({"api.js": "app.post('/login', loginLimiter, handler);\n"})
        self.assertTrue(r["rate_limited"])

    def test_mass_assignment_and_client_role_are_flagged(self):
        r = self.one({
            "api.js": (
                "app.post('/p', requireAuth, async (req, res) => {\n"
                "  await db.p.create({ data: { ...req.body, role: req.body.role } });\n"
                "});\n"
            ),
        })
        self.assertTrue(r["mass_assignment"])
        self.assertTrue(r["client_role"])

    def test_guard_after_write_is_detected_in_order(self):
        r = self.one({
            "api.js": (
                "app.patch('/p/:id', async (req, res) => {\n"
                "  await db.p.update({ where: { id: req.params.id }, data: req.body });\n"
                "  const session = await getServerSession(req);\n"
                "  if (!session) return res.status(401).end();\n"
                "});\n"
            ),
        })
        self.assertTrue(r["guard_after_write"])


# --------------------------------------------------------------------------
# rules
# --------------------------------------------------------------------------

class TestRules(Base):
    def test_unauthenticated_mutation(self):
        self.assertIn("unauthenticated_mutation", self.rules({
            "api.js": "app.delete('/p/:id', async (req, res) => { await db.p.delete(); });\n",
        }))

    def test_login_route_is_not_an_unauthenticated_mutation(self):
        self.assertNotIn("unauthenticated_mutation", self.rules({
            "api.js": "app.post('/login', loginLimiter, async (req, res) => { x(); });\n",
        }))

    def test_server_action_unguarded(self):
        self.assertIn("server_action_unguarded", self.rules({
            "app/actions.ts": "'use server';\nexport async function wipe() { await db.x.delete(); }\n",
        }))

    def test_guarded_server_action_is_not_reported(self):
        self.assertNotIn("server_action_unguarded", self.rules({
            "app/actions.ts": (
                "'use server';\n"
                "export async function wipe() {\n"
                "  const session = await auth();\n"
                "  if (!session?.user) throw new Error('unauthorised');\n"
                "  await db.x.delete({ where: { id: session.user.id } });\n"
                "}\n"
            ),
        }))

    def test_caller_supplied_identity(self):
        self.assertIn("caller_supplied_identity", self.rules({
            "app/actions.ts": "'use server';\nexport async function del(userId) { await db.u.delete(); }\n",
        }))

    def test_id_param_no_owner_check(self):
        self.assertIn("id_param_no_owner_check", self.rules({
            "api.js": (
                "app.patch('/orders/:id', requireAuth, async (req, res) => {\n"
                "  await db.order.update({ where: { id: req.params.id } });\n"
                "});\n"
            ),
        }))

    def test_scoped_query_is_not_reported_as_idor(self):
        self.assertNotIn("id_param_no_owner_check", self.rules({
            "api.js": (
                "app.patch('/orders/:id', requireAuth, async (req, res) => {\n"
                "  await db.order.updateMany({ where: { id: req.params.id, userId: req.user.id } });\n"
                "});\n"
            ),
        }))

    def test_role_gated_route_is_not_reported_as_idor(self):
        self.assertNotIn("id_param_no_owner_check", self.rules({
            "api.js": (
                "app.delete('/users/:id', requireAuth, requireRole('admin'), async (req, res) => {\n"
                "  await db.user.delete({ where: { id: req.params.id } });\n"
                "});\n"
            ),
        }))

    def test_admin_path_without_role_guard(self):
        self.assertIn("admin_path_without_role_guard", self.rules({
            "api.js": "app.get('/admin/users', requireAuth, (req, res) => {});\n",
        }))

    def test_admin_path_with_role_guard_is_not_reported(self):
        self.assertNotIn("admin_path_without_role_guard", self.rules({
            "api.js": "app.get('/admin/users', requireAuth, requireRole('admin'), h);\n",
        }))

    def test_inconsistent_sibling_guards(self):
        self.assertIn("inconsistent_sibling_guards", self.rules({
            "api.js": (
                "app.get('/api/p/one', requireAuth, h);\n"
                "app.get('/api/p/two', requireAuth, h);\n"
                "app.get('/api/p/three', h);\n"
            ),
        }))

    def test_consistent_siblings_are_not_reported(self):
        self.assertNotIn("inconsistent_sibling_guards", self.rules({
            "api.js": (
                "app.get('/api/p/one', requireAuth, h);\n"
                "app.get('/api/p/two', requireAuth, h);\n"
            ),
        }))

    def test_mass_assignment_rule(self):
        self.assertIn("mass_assignment", self.rules({
            "api.js": (
                "app.post('/p', requireAuth, async (req, res) => {\n"
                "  await db.p.create({ data: { ...req.body } });\n"
                "});\n"
            ),
        }))

    def test_public_read_of_sensitive_data(self):
        self.assertIn("public_read_of_sensitive_data", self.rules({
            "api.js": "app.get('/api/invoices', async (req, res) => { res.json(await db.invoice.findMany()); });\n",
        }))

    def test_auth_route_no_rate_limit(self):
        self.assertIn("auth_route_no_rate_limit", self.rules({
            "api.js": "app.post('/password/reset', async (req, res) => { x(); });\n",
        }))

    def test_rate_limited_auth_route_is_not_reported(self):
        self.assertNotIn("auth_route_no_rate_limit", self.rules({
            "api.js": "app.post('/password/reset', rateLimit({ max: 5 }), h);\n",
        }))

    def test_debug_route_exposed(self):
        self.assertIn("debug_route_exposed", self.rules({
            "api.js": "app.get('/debug/dump', async (req, res) => { res.json(await db.user.findMany()); });\n",
        }))

    def test_no_identity_guard_anywhere(self):
        self.assertIn("no_identity_guard_anywhere", self.rules({
            "api.js": "app.get('/a', h);\napp.get('/b', h);\n",
        }))

    def test_guard_vocabulary_drift(self):
        self.assertIn("guard_vocabulary_drift", self.rules({
            "api.js": (
                "app.get('/a', requireAuth, h);\n"
                "app.get('/b', isAuthenticated, h);\n"
                "app.get('/c', checkAuth, h);\n"
            ),
        }))

    def test_findings_are_ordered_by_severity_and_counted(self):
        doc = self.build({
            "api.js": "app.delete('/p/:id', async (req, res) => { await db.p.delete(); });\n",
        })
        report = audit.audit(doc)
        sevs = [f["severity"] for f in report["findings"]]
        self.assertEqual(sevs, sorted(sevs, key=lambda s: audit.SEVERITY_ORDER[s]))
        self.assertEqual(sum(report["counts"].values()), len(report["findings"]))

    def test_every_finding_states_a_message_and_a_reason(self):
        doc = routes.build(os.path.join(EXAMPLES, "before"))
        for f in audit.audit(doc)["findings"]:
            self.assertTrue(f["message"] and f["why"] and f["rule"], f)


# --------------------------------------------------------------------------
# the matrix
# --------------------------------------------------------------------------

class TestMatrix(Base):
    def report(self, files: dict) -> dict:
        return audit.audit(self.build(files))

    def test_public_mutation_is_an_alarm_for_anon(self):
        rep = self.report({"api.js": "app.delete('/p/:id', h);\n"})
        _r, states = render.matrix(rep)[0]
        self.assertEqual(states["anon"], "bad")

    def test_credential_endpoint_is_not_an_alarm(self):
        rep = self.report({"api.js": "app.post('/login', h);\n"})
        _r, states = render.matrix(rep)[0]
        self.assertEqual(states["anon"], "yes")

    def test_authed_route_blocks_anon(self):
        rep = self.report({"api.js": "app.get('/x', requireAuth, h);\n"})
        _r, states = render.matrix(rep)[0]
        self.assertEqual(states["anon"], "no")
        self.assertEqual(states["user"], "yes")

    def test_role_route_blocks_a_plain_user(self):
        rep = self.report({"api.js": "app.get('/x', requireAuth, requireRole('admin'), h);\n"})
        self.assertIn("admin", render.callers(rep))
        _r, states = render.matrix(rep)[0]
        self.assertEqual(states["user"], "no")
        self.assertEqual(states["admin"], "yes")

    def test_owner_route_is_scoped(self):
        rep = self.report({
            "api.js": (
                "app.get('/mine', requireAuth, async (req, res) => {\n"
                "  await db.p.findMany({ where: { userId: req.user.id } });\n"
                "});\n"
            ),
        })
        _r, states = render.matrix(rep)[0]
        self.assertEqual(states["user"], "own")

    def test_worst_rows_sort_first(self):
        rep = self.report({
            "api.js": "app.get('/a', requireAuth, h);\napp.delete('/b', h);\n",
        })
        first = render.matrix(rep)[0][0]
        self.assertEqual(first["path"], "/b")

    def test_markdown_matrix_has_a_header_and_a_legend(self):
        rep = self.report({"api.js": "app.get('/x', requireAuth, h);\n"})
        out = render.to_markdown_matrix(rep)
        self.assertIn("| Route | anon | user | guard chain |", out)
        self.assertIn("blocked", out)

    def test_html_is_self_contained_and_themed(self):
        rep = self.report({"api.js": "app.delete('/p/:id', h);\n"})
        out = render.to_html(rep)
        self.assertTrue(out.startswith("<!doctype html>"))
        self.assertIn("prefers-color-scheme: dark", out)
        self.assertIn("unauthenticated_mutation", out)
        self.assertIn("<table>", out)

    def test_html_escapes_content(self):
        rep = self.report({"api.js": "app.get('/x', requireAuth, h);\n"})
        self.assertNotIn("<script>alert", render.to_html(rep))


# --------------------------------------------------------------------------
# the shipped examples, end to end through the CLI
# --------------------------------------------------------------------------

class TestExamples(unittest.TestCase):
    def run_cli(self, script: str, *args: str):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", script), *args],
            capture_output=True, text=True,
        )

    def test_before_example_has_criticals(self):
        proc = self.run_cli("audit.py", os.path.join(EXAMPLES, "before"), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        rep = json.loads(proc.stdout)
        self.assertGreaterEqual(rep["counts"].get("critical", 0), 5)
        self.assertGreaterEqual(rep["route_count"], 12)

    def test_before_example_strict_exits_nonzero(self):
        proc = self.run_cli("audit.py", os.path.join(EXAMPLES, "before"), "--strict")
        self.assertEqual(proc.returncode, 1)

    def test_after_example_is_clean(self):
        proc = self.run_cli("audit.py", os.path.join(EXAMPLES, "after"), "--json")
        rep = json.loads(proc.stdout)
        self.assertEqual(rep["findings"], [])

    def test_after_example_has_role_and_owner_levels(self):
        proc = self.run_cli("audit.py", os.path.join(EXAMPLES, "after"), "--json")
        rep = json.loads(proc.stdout)
        self.assertGreaterEqual(rep["levels"].get("role", 0), 2)
        self.assertGreaterEqual(rep["levels"].get("owner", 0), 5)

    def test_markdown_output_is_a_table(self):
        proc = self.run_cli("audit.py", os.path.join(EXAMPLES, "before"), "--markdown")
        self.assertIn("| Severity | Route | Rule | Finding |", proc.stdout)

    def test_matrix_cli_flags_the_before_example(self):
        proc = self.run_cli("render.py", os.path.join(EXAMPLES, "before"), "--matrix")
        self.assertIn("🔴", proc.stdout)

    def test_render_writes_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "review.html")
            proc = self.run_cli("render.py", os.path.join(EXAMPLES, "before"), f"--out={dest}")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(dest, encoding="utf-8") as fh:
                self.assertIn("<table>", fh.read())

    def test_routes_cli_emits_json(self):
        proc = self.run_cli("routes.py", os.path.join(EXAMPLES, "before"))
        doc = json.loads(proc.stdout)
        self.assertIn("express", doc["frameworks"])
        self.assertIn("next", doc["frameworks"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
