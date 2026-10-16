"""Offline regression tests. IDA is not required; GUI boundaries are mocked."""

import ast
import functools
import json
import logging
from pathlib import Path
import queue
import sys
import threading
import types
import traceback
from typing import Union
import unittest
from dataclasses import dataclass, replace
from unittest.mock import patch


class DummyHook:
    def hook(self):
        return True

    def unhook(self):
        pass

    def func_printed(self, cfunc):
        pass

    def refresh_pseudocode(self, vu):
        pass


def install_ida_stubs():
    hx = types.ModuleType("ida_hexrays")
    hx.Hexrays_Hooks = DummyHook
    hx.ANCHOR_MASK, hx.ANCHOR_INDEX, hx.ANCHOR_CITEM = -1073741824, 536870911, 0
    hx.cot_num = 61
    kw = types.ModuleType("ida_kernwin")
    kw.UI_Hooks = kw.action_handler_t = DummyHook
    kw.Form = type("Form", (), {})
    for name in (
        "DropdownListControl",
        "StringInput",
        "NumericInput",
        "ChkGroupControl",
        "ButtonInput",
        "FT_RAWHEX",
        "FT_DEC",
    ):
        setattr(kw.Form, name, 0)
    kw.Choose = type("Choose", (), {})
    kw.msg = lambda text: None
    for name in (
        "action_desc_t",
        "register_action",
        "unregister_action",
        "register_timer",
        "unregister_timer",
        "get_current_widget",
        "get_widget_type",
        "find_widget",
        "attach_action_to_menu",
        "attach_action_to_popup",
    ):
        setattr(kw, name, lambda *args, **kwargs: None)
    for name in (
        "BWN_PSEUDOCODE",
        "SETMENU_APP",
        "AST_ENABLE_ALWAYS",
        "AST_ENABLE_FOR_WIDGET",
        "AST_DISABLE_FOR_WIDGET",
    ):
        setattr(kw, name, 0)
    hx.has_cached_cfunc = hx.decompile = hx.get_widget_vdui = lambda *args: None
    il = types.ModuleType("ida_lines")
    for name, value in {
        "ON": "\x01",
        "OFF": "\x02",
        "ESC": "\x03",
        "INV": "\x04",
        "ADDR": "(",
        "AUTOCMT": "\x04",
        "REGCMT": "\x02",
        "RPTCMT": "\x03",
        "KEYWORD": " ",
    }.items():
        setattr(il, "SCOLOR_" + name, value)
    il.COLOR_ADDR_SIZE = 16
    il.COLSTR = lambda text, color: "\x01" + color + text + "\x02" + color
    sys.modules.update(
        ida_hexrays=hx,
        ida_kernwin=kw,
        ida_lines=il,
        ida_nalt=types.ModuleType("ida_nalt"),
    )
    sys.modules["ida_nalt"].get_input_file_path = lambda: "fixture"


install_ida_stubs()
ROOT = Path(__file__).resolve().parents[1]
TREE = ast.parse((ROOT / "hashdb.py").read_text(encoding="utf-8"))
SUPPORT = {"sys": sys, "json": json, "traceback": traceback, "dataclass": dataclass}
support_nodes = [
    node
    for node in TREE.body
    if (
        isinstance(node, ast.FunctionDef)
        and node.name
        in ("_remember_pseudocode_algorithms", "_create_pseudocode_components")
    )
    or (
        isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_PSEUDOCODE_ALGORITHMS"
            for target in node.targets
        )
    )
]
exec(
    compile(ast.Module(body=support_nodes, type_ignores=[]), "hashdb.py", "exec"),
    SUPPORT,
)
pc = SUPPORT["_create_pseudocode_components"]()
render = pc
il = sys.modules["ida_lines"]


def anchor(index):
    return il.SCOLOR_ON + il.SCOLOR_ADDR + "%016X" % index


def response(*names):
    return {
        "hashes": [
            {
                "string": {
                    "is_api": True,
                    "api": name,
                    "modules": ["kernel32", "kernelbase"],
                }
            }
            for name in names
        ]
    }


class NumericAndCandidateTests(unittest.TestCase):
    def test_width_normalization(self):
        cases = [
            (32, 0x7C0DFCAA, 0x7C0DFCAA),
            (64, 0x7C0DFCAA, 0x7C0DFCAA),
            (64, 0xFFFFFFFFEC0E4E8E, 0xEC0E4E8E),
            (64, 0x123456787C0DFCAA, None),
            (64, 0xFFFFFFFF7C0DFCAA, None),
        ]
        for bits, value, expected in cases:
            with self.subTest(bits=bits, value=value):
                self.assertEqual(pc.normalize_for_algorithm(bits, value, 32), expected)

    def test_preferred_dll_preserves_function_collisions(self):
        self.assertEqual(
            pc.candidates_from_response(
                response("GetProcAddress", "Collision"), "KERNEL32.DLL"
            ),
            [("kernel32", "Collision"), ("kernel32", "GetProcAddress")],
        )

    def test_unknown_preference_does_not_fabricate_module(self):
        self.assertEqual(
            len(pc.candidates_from_response(response("GetProcAddress"), "invented")), 2
        )

    def test_all_modules_without_preference(self):
        self.assertEqual(
            len(pc.candidates_from_response(response("GetProcAddress"))), 2
        )

    def test_server_algorithm_name_is_preserved(self):
        target = [("kernel32", "GetProcAddress")]
        self.assertEqual(
            pc.format_candidates("ror13_add", target),
            "ror13_add: kernel32!GetProcAddress",
        )
        self.assertTrue(
            pc.format_candidates("other_algorithm", target).startswith(
                "other_algorithm: "
            )
        )
        self.assertIsNone(pc.format_candidates("ror13_add", []))

    def test_plain_string_results(self):
        data = {"hashes": [{"string": {"is_api": False, "string": "literal"}}]}
        self.assertEqual(pc.candidates_from_response(data), [("", "literal")])


class RendererTests(unittest.TestCase):
    def test_numeric_suffixes_and_tag_preservation(self):
        suffix = il.COLSTR(" ror13: kernel32!GetProcAddress", il.SCOLOR_AUTOCMT)
        for token in (
            "0x7C0DFCAAu",
            "-818824417",
            "0xFFFFFFFFULL",
            "0xFFFFFFFFFFFFFFFFui64",
            "0x80000000LL",
            "-1i64",
            "0",
            "077",
            "0b1010",
        ):
            with self.subTest(token=token):
                raw = (
                    "call(" + anchor(5) + il.COLSTR(token, il.SCOLOR_KEYWORD) + ", x);"
                )
                output = render.decorate_line(raw, {5: suffix})
                self.assertEqual(output.replace(suffix, ""), raw)
                self.assertIn(
                    il.COLSTR(token, il.SCOLOR_KEYWORD) + suffix + ",", output
                )
                self.assertEqual(
                    render._ANCHOR.findall(output), render._ANCHOR.findall(raw)
                )

    def test_existing_parameter_labels(self):
        raw = (
            anchor(5)
            + il.COLSTR("hash_to_find: ", il.SCOLOR_AUTOCMT)
            + il.COLSTR("0x7C0DFCAA", " ")
            + ");"
        )
        suffix = il.COLSTR(" resolved", il.SCOLOR_AUTOCMT)
        self.assertEqual(
            render.decorate_line(raw, {5: suffix}), raw[:-2] + suffix + ");"
        )

    def test_non_numeric_forms_not_rewritten(self):
        for text in ("Enum_0", "'1'", "sizeof(int)", '"0x1234"', "0xBADNAME"):
            with self.subTest(text=text):
                raw = anchor(5) + il.COLSTR(text, " ") + ";"
                self.assertEqual(render.decorate_line(raw, {5: " hint"}), raw)

    def test_repeated_values_and_non_ctree_anchors(self):
        raw = (
            anchor(5) + il.COLSTR("123", " ") + ", " + anchor(6) + il.COLSTR("123", " ")
        )
        self.assertEqual(render.decorate_line(raw, {5: " H", 6: " H"}).count(" H"), 2)
        raw = anchor(0x80000005) + il.COLSTR("123", " ")
        self.assertEqual(render.decorate_line(raw, {5: " H"}), raw)

    def test_idempotence_and_disabling_restore_original(self):
        raw = anchor(0) + il.COLSTR("0x7C0DFCAA", " ") + ";"
        output = [types.SimpleNamespace(line=raw)]
        expr = types.SimpleNamespace(
            type=types.SimpleNamespace(get_size=lambda: 4), numval=lambda: 0x7C0DFCAA
        )
        cfunc = types.SimpleNamespace(
            entry_ea=0x1000,
            treeitems=[types.SimpleNamespace(op=61, cexpr=expr)],
            get_pseudocode=lambda: output,
        )
        renderer = render.HintRenderer()
        renderer.hints[(32, 0x7C0DFCAA)] = "ror13: kernel32!GetProcAddress"
        renderer.decorate(cfunc)
        once = output[0].line
        self.assertNotEqual(once, raw)
        renderer.decorate(cfunc)
        self.assertEqual(output[0].line, once)
        renderer.enabled = False
        renderer.decorate(cfunc)
        self.assertEqual(output[0].line, raw)

    def test_label_cannot_inject_control_codes(self):
        self.assertEqual(render._clean_label("bad\x01\x02\x03\x04\ntext"), "bad text")


class ScanLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.scanner = pc.PseudocodeScanner.__new__(pc.PseudocodeScanner)
        self.scanner.alive, self.scanner.job = True, None
        self.scanner.database, self.scanner.epoch = "fixture", 1
        self.scanner._instance_token = object()
        self.scanner.events = queue.Queue()
        self.scanner.cancel_event = None
        self.scanner.last_error = self.scanner.last_result = None
        self.scanner.choosers = []
        self.scanner.algorithms = [("ror13_add", 32)]
        self.scanner.backend = types.SimpleNamespace(
            HASHDB_ALGORITHM="ror13_add",
            HASHDB_ALGORITHM_SIZE=32,
            HASHDB_API_URL="https://hashdb.openanalysis.net",
            HASHDB_REQUEST_LOCK=threading.Lock(),
            _PSEUDOCODE_ALGORITHMS={
                "https://hashdb.openanalysis.net": (("ror13_add", 32),)
            },
        )
        self.scanner.renderer = types.SimpleNamespace(
            by_function={}, enabled=False, refresh=lambda: None
        )
        self.base = pc.ScanSpec(
            0x1000,
            "fixture",
            1,
            "ror13_add",
            32,
            0,
            "https://hashdb.openanalysis.net",
            "kernel32",
            True,
            ((32, 0x7C0DFCAA), (64, 0x7C0DFCAA)),
        )
        self.normal = dict.fromkeys(self.base.keys, 0x7C0DFCAA)
        self.results = {0x7C0DFCAA: [("kernel32", "GetProcAddress")]}

    def test_invalid_specs_rejected_before_network(self):
        for field in (
            {"epoch": 0},
            {"xor": 1 << 32},
            {"algorithm_bits": 16},
            {"api_url": "file:///tmp"},
            {"max_requests": 0},
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.scanner.scan(replace(self.base, **field))

    def test_concurrent_scan_rejected(self):
        self.scanner.job = object()
        with self.assertRaises(RuntimeError):
            self.scanner.scan(self.base)

    def test_failed_cancelled_and_stale_jobs_do_not_publish(self):
        published = []
        self.scanner.publish = lambda *args: published.append(args)
        for spec, error, cancelled in (
            (self.base, "network failed", False),
            (self.base, None, True),
            (replace(self.base, epoch=0), None, False),
        ):
            token = self.scanner.job = object()
            self.scanner.events.put(
                ("scan", token, spec, self.normal, self.results, error, cancelled)
            )
            self.scanner.poll()
        self.assertEqual(published, [])

    def test_wrong_token_ignored_and_matching_job_published_once(self):
        published = []
        self.scanner.publish = lambda *args: published.append(args)
        token = self.scanner.job = object()
        self.scanner.events.put(
            ("scan", object(), self.base, self.normal, self.results, None, False)
        )
        self.scanner.poll()
        self.assertIs(self.scanner.job, token)
        self.scanner.events.put(
            ("scan", token, self.base, self.normal, self.results, None, False)
        )
        self.scanner.poll()
        self.assertEqual(len(published), 1)

    def test_pre_cancelled_worker_makes_no_request_and_releases_lock(self):
        calls = []
        self.scanner.backend = types.SimpleNamespace(
            get_strings_from_hash=lambda *a, **k: calls.append(a)
        )
        cancel = threading.Event()
        cancel.set()
        lock = threading.Lock()
        lock.acquire()
        self.scanner.worker(
            object(), cancel, self.base, self.normal, [0x7C0DFCAA], lock
        )
        self.assertEqual(calls, [])
        self.assertFalse(lock.locked())

    def test_hunt_context_has_no_ctree_objects(self):
        self.scanner.current = lambda quiet=False: types.SimpleNamespace(
            entry_ea=0x1000
        )
        self.scanner.collect = lambda cfunc: self.base.keys
        context = self.scanner.capture_context()
        self.assertEqual(context[1:], (0x1000, "fixture", 1, self.base.keys))
        self.assertIs(context[0], self.scanner._instance_token)

    def test_stale_hunt_context_does_not_open_form(self):
        context = (self.scanner._instance_token, 0x1000, "fixture", 1, self.base.keys)
        for stale in (
            (object(),) + context[1:],
            context[:3] + (0, context[4]),
            context[:2] + ("other",) + context[3:],
        ):
            with patch.object(pc.ScanForm, "__new__") as form:
                self.scanner.open_dialog(stale)
                form.assert_not_called()

    def test_cancel_scan_options_does_not_start_scan(self):
        context = (self.scanner._instance_token, 0x1000, "fixture", 1, self.base.keys)
        cancelled = types.SimpleNamespace(ask=lambda: None)
        with (
            patch.object(pc.ScanForm, "__new__", return_value=cancelled) as form,
            patch.object(self.scanner, "scan") as scan,
        ):
            self.scanner.open_dialog(context)
            form.assert_called_once_with(
                pc.ScanForm, self.scanner, 0x1000, self.base.keys
            )
            scan.assert_not_called()

    def test_hunt_algorithm_not_fetched_cannot_open_scan(self):
        self.scanner.backend.HASHDB_ALGORITHM = "new_custom_hash"
        self.scanner.backend.HASHDB_ALGORITHM_SIZE = 64
        self.scanner.last_algorithm = "ror13_add"
        context = (self.scanner._instance_token, 0x1000, "fixture", 1, self.base.keys)
        with patch.object(pc.ScanForm, "__new__") as form:
            self.scanner.open_dialog(context)
            form.assert_not_called()
        self.assertNotIn(("new_custom_hash", 64), self.scanner.algorithms)

    def test_scan_and_publish_require_server_metadata(self):
        for change in (
            {"api_url": "https://other.example"},
            {"algorithm": "unknown"},
            {"algorithm_bits": 64},
        ):
            spec = replace(self.base, **change)
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, "Fetch algorithms"):
                    self.scanner.scan(spec)
                with self.assertRaisesRegex(ValueError, "Fetch algorithms"):
                    self.scanner.publish(spec, self.normal, self.results)
                self.assertFalse(self.scanner.backend.HASHDB_REQUEST_LOCK.locked())

    def test_no_catalog_does_not_open_form(self):
        self.scanner.backend._PSEUDOCODE_ALGORITHMS.clear()
        context = (self.scanner._instance_token, 0x1000, "fixture", 1, self.base.keys)
        with patch.object(pc.ScanForm, "__new__") as form:
            self.scanner.open_dialog(context)
            form.assert_not_called()

    def test_catalog_responses_follow_form_server_and_latest_request(self):
        token = object()
        updates = []
        server = "https://hashdb.openanalysis.net"
        form = types.SimpleNamespace(
            alive=True,
            catalog_request=token,
            server=object(),
            GetControlValue=lambda field: server,
            update_catalog=updates.append,
        )
        rows = [("server_algorithm", 64)]
        for alive, reply_token, reply_server in (
            (False, token, server),
            (True, object(), server),
            (True, token, "https://other.example"),
        ):
            form.alive = alive
            self.scanner.events.put(
                ("catalog", form, reply_server, reply_token, rows, None)
            )
            self.scanner.poll()
        self.assertEqual(updates, [])
        form.alive = True
        self.scanner.events.put(("catalog", form, server, token, rows, None))
        self.scanner.poll()
        self.assertEqual(updates, [rows])
        self.assertEqual(self.scanner.algorithms, rows)


class HuntIntegrationTests(unittest.TestCase):
    """Exercise the actual Hunt functions without importing unrelated IDA code."""

    def setUp(self):
        tree = ast.parse((ROOT / "hashdb.py").read_text(encoding="utf-8"))
        functions = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name in ("hunt_algorithm_done", "hunt_algorithm_run")
        ]
        self.lock = threading.Lock()
        self.lock.acquire()
        self.context = ("scanner", 0x1000, "fixture", 1, ((32, 123),))
        self.offered = []
        scanner = types.SimpleNamespace(
            capture_context=lambda: self.context,
            open_dialog=lambda ctx: self.offered.append((ctx, self.lock.locked())),
        )
        self.worker = None

        def worker(**kwargs):
            self.worker = types.SimpleNamespace(**kwargs, start=lambda: None)
            return self.worker

        self.env = dict(
            Union=Union,
            logging=logging,
            functools=functools,
            HASHDB_REQUEST_LOCK=self.lock,
            HASHDB_USE_XOR=False,
            HASHDB_PLUGIN_OBJECT=types.SimpleNamespace(_pseudocode=scanner),
            idaapi=types.SimpleNamespace(msg=lambda text: None),
            ida_kernwin=types.SimpleNamespace(
                execute_sync=lambda fn, flags: fn(), MFF_FAST=0
            ),
            hunt_result_form_t=types.SimpleNamespace(show=lambda response: True),
            parse_highlighted_value=lambda: 123,
            HashDBError=ValueError,
            hunt_algorithm_request=lambda *args: None,
            hunt_algorithm_error=lambda: None,
            Worker=worker,
        )
        exec(
            compile(ast.Module(body=functions, type_ignores=[]), "hashdb.py", "exec"),
            self.env,
        )

    def test_selection_offers_origin_after_releasing_lock(self):
        self.assertFalse(self.env["hunt_algorithm_run"]())
        self.worker.done_callback([["ror13_add", 32]])
        self.assertEqual(self.offered, [(self.context, False)])
        self.assertFalse(self.lock.locked())

    def test_hunt_cancel_or_no_result_does_not_offer_scan(self):
        for result in (None, []):
            if not self.lock.locked():
                self.lock.acquire()
            self.env["hunt_result_form_t"].show = lambda response: False
            self.env["hunt_algorithm_done"](result, self.context)
            self.assertFalse(self.lock.locked())
        self.assertEqual(self.offered, [])

    def test_disassembly_hunt_does_not_offer_scan(self):
        self.env["hunt_algorithm_done"]([["ror13_add", 32]])
        self.assertEqual(self.offered, [])
        self.assertFalse(self.lock.locked())

    def test_followup_failure_cannot_trigger_double_release(self):
        def fail(ctx):
            raise RuntimeError("UI unavailable")

        self.env["HASHDB_PLUGIN_OBJECT"]._pseudocode.open_dialog = fail
        with self.assertLogs(level="ERROR"):
            self.env["hunt_algorithm_done"]([["ror13_add", 32]], self.context)
        self.assertFalse(self.lock.locked())


class AlgorithmFetchTests(unittest.TestCase):
    def setUp(self):
        self.env = dict(SUPPORT)
        self.env["_PSEUDOCODE_ALGORITHMS"] = {}
        # Bind the helper and the existing HTTP client to one isolated cache.
        functions = [
            node
            for node in TREE.body
            if isinstance(node, ast.FunctionDef)
            and node.name
            in (
                "_remember_pseudocode_algorithms",
                "get_algorithms",
                "determine_algorithm_size",
            )
        ]
        self.env.update(
            HASHDB_REQUEST_TIMEOUT=15,
            HashDBError=RuntimeError,
            idaapi=types.SimpleNamespace(msg=lambda text: None),
        )
        self.response = types.SimpleNamespace(
            ok=True,
            json=lambda: {
                "algorithms": [
                    {"algorithm": "server_custom", "type": "unsigned_int"},
                    {"algorithm": "server_64", "type": "unsigned_long"},
                ]
            },
        )
        self.calls = []
        self.env["requests"] = types.SimpleNamespace(get=self.get)
        exec(
            compile(ast.Module(body=functions, type_ignores=[]), "hashdb.py", "exec"),
            self.env,
        )

    def get(self, url, timeout):
        self.calls.append((url, timeout))
        return self.response

    def test_catalog_is_empty_until_real_client_is_invoked(self):
        self.assertEqual(self.env["_PSEUDOCODE_ALGORITHMS"], {})
        rows = self.env["get_algorithms"](api_url="https://server.example", timeout=7)
        self.assertEqual(self.calls, [("https://server.example/hash", 7)])
        self.assertEqual(rows, [["server_custom", "32"], ["server_64", "64"]])
        self.assertEqual(
            self.env["_PSEUDOCODE_ALGORITHMS"],
            {"https://server.example": (("server_64", 64), ("server_custom", 32))},
        )

    def test_failed_fetch_does_not_seed_a_catalog(self):
        self.response.ok, self.response.status_code = False, 503
        with self.assertRaises(RuntimeError):
            self.env["get_algorithms"](api_url="https://server.example")
        self.assertEqual(self.env["_PSEUDOCODE_ALGORITHMS"], {})

    def test_refresh_replaces_catalog_without_inventing_algorithms(self):
        self.env["get_algorithms"](api_url="https://server.example")
        self.response.json = lambda: {"algorithms": []}
        self.env["get_algorithms"](api_url="https://server.example")
        self.assertEqual(
            self.env["_PSEUDOCODE_ALGORITHMS"], {"https://server.example": ()}
        )


class CompatibilityTests(unittest.TestCase):
    def test_missing_form_control_is_rejected_before_hooks(self):
        form = sys.modules["ida_kernwin"].Form
        with patch.object(form, "DropdownListControl"):
            del form.DropdownListControl
            with self.assertRaisesRegex(RuntimeError, "DropdownListControl"):
                SUPPORT["_create_pseudocode_components"]()

    def test_missing_api_is_rejected_before_hooks_or_actions(self):
        hx = sys.modules["ida_hexrays"]
        with patch.dict(hx.__dict__, clear=False):
            del hx.ANCHOR_MASK
            with (
                patch.object(DummyHook, "hook") as hook,
                self.assertRaisesRegex(RuntimeError, "ANCHOR_MASK"),
            ):
                SUPPORT["_create_pseudocode_components"]()
            hook.assert_not_called()

    def test_missing_print_event_is_rejected_before_hooks(self):
        with patch.object(
            sys.modules["ida_hexrays"], "Hexrays_Hooks", type("OldHooks", (), {})
        ):
            with self.assertRaisesRegex(RuntimeError, "func_printed"):
                SUPPORT["_create_pseudocode_components"]()

    def test_old_python_is_rejected_before_importing_optional_modules(self):
        with (
            patch.object(sys, "version_info", (3, 8)),
            patch.dict(sys.modules, {"ida_hexrays": None}),
        ):
            with self.assertRaisesRegex(RuntimeError, "Python 3.9"):
                SUPPORT["_create_pseudocode_components"]()

    def test_startup_does_not_fetch_algorithms_or_hashes(self):
        def unexpected_request(*args, **kwargs):
            raise AssertionError("Unexpected startup request")

        backend = types.SimpleNamespace(
            HASHDB_ALGORITHM=None,
            get_algorithms=unexpected_request,
            get_strings_from_hash=unexpected_request,
        )
        kw = sys.modules["ida_kernwin"]
        with (
            patch.object(kw, "register_action", return_value=True),
            patch.object(kw, "register_timer", return_value=object()),
        ):
            scanner = pc.PseudocodeScanner(backend)
            try:
                self.assertEqual(scanner.algorithms, [])
                self.assertIsNone(scanner.last_algorithm)
            finally:
                scanner.stop()

    def test_unsupported_ida_retains_legacy_callback(self):
        plugin_class = next(
            node
            for node in TREE.body
            if isinstance(node, ast.ClassDef) and node.name == "HashDB_Plugin_t"
        )
        method = next(
            node
            for node in plugin_class.body
            if isinstance(node, ast.FunctionDef) and node.name == "_init_hexrays_hooks"
        )
        callbacks, messages = [], []
        env = dict(
            SUPPORT,
            idaapi=types.SimpleNamespace(
                init_hexrays_plugin=lambda: True,
                install_hexrays_callback=lambda callback: callbacks.append(callback),
                msg=messages.append,
            ),
        )
        exec(
            compile(ast.Module(body=[method], type_ignores=[]), "hashdb.py", "exec"),
            env,
        )
        plugin = types.SimpleNamespace(
            _hexrays_hooked=False,
            _pseudocode=None,
            _hooks=types.SimpleNamespace(hxe_callback=object()),
        )
        with patch.dict(sys.modules, {"ida_hexrays": None}):
            env["_init_hexrays_hooks"](plugin)
        self.assertTrue(plugin._hexrays_hooked)
        self.assertIsNone(plugin._pseudocode)
        self.assertEqual(callbacks, [plugin._hooks.hxe_callback])
        self.assertIn("legacy actions remain enabled", "".join(messages))


if __name__ == "__main__":
    unittest.main()
