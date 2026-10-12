"""The "Waiting for HSM response" overlay must cover every HSM-reaching route.

A hand-maintained list in the portal would rot: someone adds a route that signs,
forgets the list, and that operation silently looks idle for the several seconds
a hardware token takes. So the set is *derived* here from the call graph of
``create_app`` and compared against the list the portal actually ships. Add a
route that reaches the signing backend and this test fails until it is listed.

The derivation is deliberately conservative: it seeds on direct contact with the
HSM proxy, the SmartCard-HSM tooling, the ceremony/recovery services, or an
issuance call, then propagates through locally defined helpers.
"""
from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

import myownca.online.app as app_module

APP_SOURCE = Path(app_module.__file__)
STATIC = APP_SOURCE.parent / "static"

SEED_OBJECTS = {"hsm", "scctl", "ceremony", "hsm_ceremony_service", "hsm_recovery_service"}
SEED_SERVICE_METHODS = {
    "issue_certificate",
    "sign_certificate",
    "sign_csr",
    "sign_crl",
    "sign_data",
    "generate_key",
    "public_key",
    "private_key",
    "build_sub_ca_certificate",
    "create_lab_ca_chain",
}
ROUTE_DECORATORS = {"get", "post", "put", "delete", "patch"}


def _create_app_node() -> ast.FunctionDef:
    tree = ast.parse(APP_SOURCE.read_text())
    return next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "create_app"
    )


def _collect(create_app: ast.FunctionDef):
    functions: dict[str, ast.AST] = {}
    routes: dict[str, list[tuple[str, str]]] = {}

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node):  # noqa: N802 - ast API
            functions[node.name] = node
            for decorator in node.decorator_list:
                if (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and isinstance(decorator.func.value, ast.Name)
                    and decorator.func.value.id == "app"
                    and decorator.func.attr in ROUTE_DECORATORS
                    and decorator.args
                    and isinstance(decorator.args[0], ast.Constant)
                ):
                    routes.setdefault(node.name, []).append(
                        (decorator.func.attr.upper(), decorator.args[0].value)
                    )
            self.generic_visit(node)

        visit_AsyncFunctionDef = visit_FunctionDef

    Visitor().visit(create_app)
    return functions, routes


def _touches_hsm(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
            if sub.value.id in SEED_OBJECTS:
                return True
            if sub.value.id == "service" and sub.attr in SEED_SERVICE_METHODS:
                return True
        if isinstance(sub, ast.Name) and sub.id in SEED_OBJECTS:
            return True
    return False


def hsm_reaching_routes() -> set[tuple[str, str]]:
    functions, routes = _collect(_create_app_node())
    reaching = {name for name, node in functions.items() if _touches_hsm(node)}
    calls = {
        name: {
            sub.func.id
            for sub in ast.walk(node)
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
        }
        & set(functions)
        for name, node in functions.items()
    }
    changed = True
    while changed:
        changed = False
        for name, callees in calls.items():
            if name not in reaching and callees & reaching:
                reaching.add(name)
                changed = True
    return {route for name in reaching for route in routes.get(name, ())}


def portal_busy_routes() -> list[tuple[str, str]]:
    """Parse HSM_BUSY_ROUTES out of the shared portal script."""

    script = (STATIC / "app_shared.js").read_text()
    block = script.split("const HSM_BUSY_ROUTES = [", 1)[1].split("].map(", 1)[0]
    return re.findall(r'\["([A-Z]+)",\s*"([^"]+)"\]', block)


def _covers(patterns: list[tuple[str, str]], method: str, path: str) -> bool:
    # The portal matches concrete URLs; the route table has {param} placeholders.
    concrete = re.sub(r"\{[^}]+\}", "placeholder", path)
    return any(
        route_method == method and re.fullmatch(pattern, concrete)
        for route_method, pattern in patterns
    )


class HsmBusyRouteCoverageTests(unittest.TestCase):
    def test_every_hsm_reaching_route_shows_the_busy_overlay(self) -> None:
        patterns = portal_busy_routes()
        missing = sorted(
            f"{method} {path}"
            for method, path in hsm_reaching_routes()
            if not _covers(patterns, method, path)
        )
        self.assertEqual(
            missing,
            [],
            "These routes can reach the signing backend but would show no "
            "'Waiting for HSM response' overlay. Add them to HSM_BUSY_ROUTES in "
            "app_shared.js:\n  " + "\n  ".join(missing),
        )

    def test_the_derivation_finds_the_obvious_signing_routes(self) -> None:
        """Guard the analysis itself: if it silently found nothing, the coverage
        assertion above would pass vacuously."""
        reaching = hsm_reaching_routes()
        self.assertIn(("POST", "/internal/hsm/keys"), reaching)
        self.assertIn(("POST", "/internal/certificate-requests/{request_id}/approvals"), reaching)
        self.assertGreater(len(reaching), 15)

    def test_plain_reads_do_not_block_the_ui(self) -> None:
        """Over-inclusion would freeze the portal on routine calls."""
        patterns = portal_busy_routes()
        for method, path in (
            ("GET", "/internal/certificate-requests"),
            ("GET", "/internal/people"),
            ("GET", "/internal/auth/me"),
            ("GET", "/internal/certificates"),
            ("POST", "/internal/people"),
        ):
            self.assertFalse(
                _covers(patterns, method, path),
                f"{method} {path} does not touch the HSM but would block the UI",
            )


class HsmBusyOverlayWiringTests(unittest.TestCase):
    def _shared(self) -> str:
        return (STATIC / "app_shared.js").read_text()

    def test_both_fetch_wrappers_go_through_the_indicator(self) -> None:
        script = self._shared()
        self.assertIn("if (!isHsmRoute(path, options.method)) return apiRequest(", script)
        self.assertIn(
            "if (!isHsmRoute(path, options.method)) return apiDownloadRequest(", script
        )

    def test_the_overlay_lifts_even_when_the_call_fails(self) -> None:
        """A failed HSM call must not leave the portal permanently blocked.

        Both wrappers funnel through withHsmGuards, so one finally covers both;
        what matters is that releasing the overlay is unconditional.
        """
        script = self._shared()
        guards = script.split("async function withHsmGuards", 1)[1].split("\n  }", 1)[0]
        self.assertIn("} finally {", guards)
        self.assertIn("endHsmBusy();", guards.split("} finally {", 1)[1])
        self.assertEqual(script.count("beginHsmBusy();"), 1)

    def test_the_overlay_announces_itself_and_blocks_input(self) -> None:
        script = self._shared()
        self.assertIn("Waiting for HSM response", script)
        self.assertIn('overlay.setAttribute("role", "alert")', script)
        self.assertIn('overlay.setAttribute("aria-busy", "true")', script)
        self.assertIn('document.addEventListener("keydown", swallowKeys, true)', script)

    def test_concurrent_calls_share_one_overlay(self) -> None:
        script = self._shared()
        self.assertIn("hsmBusyDepth = Math.max(0, hsmBusyDepth - 1)", script)
        self.assertIn("if (hsmBusyDepth === 0) hideHsmBusy();", script)

    def test_the_overlay_sits_above_modals(self) -> None:
        css = (STATIC / "app.css").read_text()
        busy = css.split(".busy-overlay {", 1)[1].split("}", 1)[0]
        modal = css.split(".modal-overlay {", 1)[1].split("}", 1)[0]
        busy_z = int(re.search(r"z-index:\s*(\d+)", busy).group(1))
        modal_z = int(re.search(r"z-index:\s*(\d+)", modal).group(1))
        self.assertGreater(busy_z, modal_z)


class HsmTimeoutTests(unittest.TestCase):
    """A token that never answers must not strand the operator behind the overlay."""

    def _shared(self) -> str:
        return (STATIC / "app_shared.js").read_text()

    def test_hsm_calls_are_bounded_by_a_timeout(self) -> None:
        script = self._shared()
        # 120s deliberately: a slow-but-healthy RSA-4096 keygen or token backup
        # must not be reported as a failure.
        self.assertIn("const HSM_TIMEOUT_MS = 120000;", script)
        self.assertIn("new AbortController()", script)
        self.assertIn("controller.abort();", script)
        self.assertIn("signal: controller.signal", script)

    def test_the_timer_actually_uses_the_timeout_constant(self) -> None:
        """Declaring the constant proves nothing if the timer ignores it: a
        literal here would leave the bound silently disabled."""
        script = self._shared()
        guards = script.split("async function withHsmGuards", 1)[1].split("\n  }", 1)[0]
        timer = guards.split("setTimeout(", 1)[1].split("}, ", 1)[1].split(")", 1)[0]
        self.assertEqual(timer.strip(), "HSM_TIMEOUT_MS")

    def test_both_wrappers_share_the_timeout_guard(self) -> None:
        """Neither api() nor apiDownload() may bypass the bound."""
        script = self._shared()
        self.assertEqual(script.count("return withHsmGuards(options,"), 2)
        self.assertIn("clearTimeout(timer);", script)

    def test_the_message_is_derived_from_the_timeout_constant(self) -> None:
        """A hardcoded duration would start lying the moment the bound moved --
        as it just did, going from 30s to 120s."""
        script = self._shared()
        self.assertIn("${Math.round(HSM_TIMEOUT_MS / 1000)} seconds", script)

    def test_the_message_admits_the_work_may_have_completed(self) -> None:
        """Cancelling the request does not stop the server. An operator who reads
        'timed out' as 'nothing happened' could issue the same certificate twice."""
        script = self._shared()
        message = script.split("HSM_TIMEOUT_MESSAGE =", 1)[1].split(";", 1)[0]
        self.assertIn("may", message)
        self.assertIn("still have completed on the server", message)
        self.assertIn("before retrying", message)

    def test_an_uncaught_timeout_is_still_reported(self) -> None:
        script = self._shared()
        self.assertIn('window.addEventListener("unhandledrejection"', script)
        self.assertIn("event.reason.hsmTimeout", script)
        self.assertIn("event.preventDefault();", script)

    def test_the_abort_error_is_translated(self) -> None:
        """A raw AbortError reads 'The user aborted a request', which is a lie."""
        script = self._shared()
        self.assertIn("if (timedOut) {", script)
        self.assertIn("timeout.hsmTimeout = true;", script)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
