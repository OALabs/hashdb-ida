"""Offline regression tests. IDA is not required; GUI boundaries are mocked."""
import importlib.util
import ast
import functools
import logging
from pathlib import Path
import queue
import sys
import threading
import types
import traceback
from typing import Union
import unittest
from dataclasses import replace
from unittest.mock import patch


class DummyHook:
    def hook(self):
        return True

    def unhook(self):
        pass


def install_ida_stubs():
    hx = types.ModuleType('ida_hexrays')
    hx.Hexrays_Hooks = DummyHook
    hx.ANCHOR_MASK, hx.ANCHOR_INDEX, hx.ANCHOR_CITEM = -1073741824, 536870911, 0
    hx.cot_num = 61
    kw = types.ModuleType('ida_kernwin')
    kw.UI_Hooks = kw.action_handler_t = DummyHook
    kw.Form = type('Form', (), {})
    kw.Choose = type('Choose', (), {})
    kw.msg = lambda text: None
    il = types.ModuleType('ida_lines')
    for name, value in {'ON': '\x01', 'OFF': '\x02', 'ESC': '\x03', 'INV': '\x04',
                        'ADDR': '(', 'AUTOCMT': '\x04', 'REGCMT': '\x02',
                        'RPTCMT': '\x03', 'KEYWORD': ' '}.items():
        setattr(il, 'SCOLOR_' + name, value)
    il.COLOR_ADDR_SIZE = 16
    il.COLSTR = lambda text, color: '\x01' + color + text + '\x02' + color
    sys.modules.update(ida_hexrays=hx, ida_kernwin=kw, ida_lines=il,
                       ida_nalt=types.ModuleType('ida_nalt'))


install_ida_stubs()
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hashdb_scan_under_test', ROOT / 'hashdb_pseudocode.py')
pc = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pc
spec.loader.exec_module(pc)
render = pc.renderer
il = sys.modules['ida_lines']


def anchor(index):
    return il.SCOLOR_ON + il.SCOLOR_ADDR + '%016X' % index


def response(*names):
    return {'hashes': [{'string': {'is_api': True, 'api': name,
                                   'modules': ['kernel32', 'kernelbase']}} for name in names]}


class NumericAndCandidateTests(unittest.TestCase):
    def test_width_normalization(self):
        cases = [(32, 0x7C0DFCAA, 0x7C0DFCAA), (64, 0x7C0DFCAA, 0x7C0DFCAA),
                 (64, 0xFFFFFFFFEC0E4E8E, 0xEC0E4E8E),
                 (64, 0x123456787C0DFCAA, None), (64, 0xFFFFFFFF7C0DFCAA, None)]
        for bits, value, expected in cases:
            with self.subTest(bits=bits, value=value):
                self.assertEqual(pc.normalize_for_algorithm(bits, value, 32), expected)

    def test_preferred_dll_preserves_function_collisions(self):
        self.assertEqual(pc.candidates_from_response(response('GetProcAddress', 'Collision'), 'KERNEL32.DLL'),
                         [('kernel32', 'Collision'), ('kernel32', 'GetProcAddress')])

    def test_unknown_preference_does_not_fabricate_module(self):
        self.assertEqual(len(pc.candidates_from_response(response('GetProcAddress'), 'invented')), 2)

    def test_all_modules_without_preference(self):
        self.assertEqual(len(pc.candidates_from_response(response('GetProcAddress'))), 2)

    def test_alias_and_unknown_algorithm(self):
        target = [('kernel32', 'GetProcAddress')]
        self.assertEqual(pc.format_candidates('ror13_add', target), 'ror13: kernel32!GetProcAddress')
        self.assertTrue(pc.format_candidates('other_algorithm', target).startswith('other_algorithm: '))
        self.assertIsNone(pc.format_candidates('ror13_add', []))

    def test_plain_string_results(self):
        data = {'hashes': [{'string': {'is_api': False, 'string': 'literal'}}]}
        self.assertEqual(pc.candidates_from_response(data), [('', 'literal')])


class RendererTests(unittest.TestCase):
    def test_numeric_suffixes_and_tag_preservation(self):
        suffix = il.COLSTR(' ror13: kernel32!GetProcAddress', il.SCOLOR_AUTOCMT)
        for token in ('0x7C0DFCAAu', '-818824417', '0xFFFFFFFFULL', '0xFFFFFFFFFFFFFFFFui64',
                      '0x80000000LL', '-1i64', '0', '077', '0b1010'):
            with self.subTest(token=token):
                raw = 'call(' + anchor(5) + il.COLSTR(token, il.SCOLOR_KEYWORD) + ', x);'
                output = render.decorate_line(raw, {5: suffix})
                self.assertEqual(output.replace(suffix, ''), raw)
                self.assertIn(il.COLSTR(token, il.SCOLOR_KEYWORD) + suffix + ',', output)
                self.assertEqual(render._ANCHOR.findall(output), render._ANCHOR.findall(raw))

    def test_existing_parameter_labels(self):
        raw = anchor(5) + il.COLSTR('hash_to_find: ', il.SCOLOR_AUTOCMT) + il.COLSTR('0x7C0DFCAA', ' ') + ');'
        suffix = il.COLSTR(' resolved', il.SCOLOR_AUTOCMT)
        self.assertEqual(render.decorate_line(raw, {5: suffix}), raw[:-2] + suffix + ');')

    def test_non_numeric_forms_not_rewritten(self):
        for text in ('Enum_0', "'1'", 'sizeof(int)', '"0x1234"', '0xBADNAME'):
            with self.subTest(text=text):
                raw = anchor(5) + il.COLSTR(text, ' ') + ';'
                self.assertEqual(render.decorate_line(raw, {5: ' hint'}), raw)

    def test_repeated_values_and_non_ctree_anchors(self):
        raw = anchor(5) + il.COLSTR('123', ' ') + ', ' + anchor(6) + il.COLSTR('123', ' ')
        self.assertEqual(render.decorate_line(raw, {5: ' H', 6: ' H'}).count(' H'), 2)
        raw = anchor(0x80000005) + il.COLSTR('123', ' ')
        self.assertEqual(render.decorate_line(raw, {5: ' H'}), raw)

    def test_idempotence_and_disabling_restore_original(self):
        raw = anchor(0) + il.COLSTR('0x7C0DFCAA', ' ') + ';'
        output = [types.SimpleNamespace(line=raw)]
        expr = types.SimpleNamespace(type=types.SimpleNamespace(get_size=lambda: 4), numval=lambda: 0x7C0DFCAA)
        cfunc = types.SimpleNamespace(entry_ea=0x1000, treeitems=[types.SimpleNamespace(op=61, cexpr=expr)],
                                      get_pseudocode=lambda: output)
        renderer = render.HintRenderer()
        renderer.hints[(32, 0x7C0DFCAA)] = 'ror13: kernel32!GetProcAddress'
        renderer.decorate(cfunc)
        once = output[0].line
        self.assertNotEqual(once, raw)
        renderer.decorate(cfunc)
        self.assertEqual(output[0].line, once)
        renderer.enabled = False
        renderer.decorate(cfunc)
        self.assertEqual(output[0].line, raw)

    def test_label_cannot_inject_control_codes(self):
        self.assertEqual(render._clean_label('bad\x01\x02\x03\x04\ntext'), 'bad text')


class ScanLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.scanner = pc.PseudocodeScanner.__new__(pc.PseudocodeScanner)
        self.scanner.alive, self.scanner.job = True, None
        self.scanner.database, self.scanner.epoch = 'fixture', 1
        self.scanner._instance_token = object()
        self.scanner.events = queue.Queue()
        self.scanner.cancel_event = None
        self.scanner.last_error = self.scanner.last_result = None
        self.scanner.choosers = []
        self.scanner.algorithms = [('ror13_add', 32)]
        self.scanner.renderer = types.SimpleNamespace(by_function={}, enabled=False, refresh=lambda: None)
        self.base = pc.ScanSpec(0x1000, 'fixture', 1, 'ror13_add', 32, 0,
                                'https://hashdb.openanalysis.net', 'kernel32', True,
                                ((32, 0x7C0DFCAA), (64, 0x7C0DFCAA)))
        self.normal = dict.fromkeys(self.base.keys, 0x7C0DFCAA)
        self.results = {0x7C0DFCAA: [('kernel32', 'GetProcAddress')]}

    def test_invalid_specs_rejected_before_network(self):
        for field in ({'epoch': 0}, {'xor': 1 << 32}, {'algorithm_bits': 16},
                      {'api_url': 'file:///tmp'}, {'max_requests': 0}):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.scanner.scan(replace(self.base, **field))

    def test_concurrent_scan_rejected(self):
        self.scanner.job = object()
        with self.assertRaises(RuntimeError):
            self.scanner.scan(self.base)

    def test_failed_cancelled_and_stale_jobs_do_not_publish(self):
        published = []
        self.scanner.publish = lambda *args: published.append(args)
        for spec, error, cancelled in ((self.base, 'network failed', False),
                                       (self.base, None, True), (replace(self.base, epoch=0), None, False)):
            token = self.scanner.job = object()
            self.scanner.events.put(('scan', token, spec, self.normal, self.results, error, cancelled))
            self.scanner.poll()
        self.assertEqual(published, [])

    def test_wrong_token_ignored_and_matching_job_published_once(self):
        published = []
        self.scanner.publish = lambda *args: published.append(args)
        token = self.scanner.job = object()
        self.scanner.events.put(('scan', object(), self.base, self.normal, self.results, None, False))
        self.scanner.poll()
        self.assertIs(self.scanner.job, token)
        self.scanner.events.put(('scan', token, self.base, self.normal, self.results, None, False))
        self.scanner.poll()
        self.assertEqual(len(published), 1)

    def test_pre_cancelled_worker_makes_no_request_and_releases_lock(self):
        calls = []
        self.scanner.backend = types.SimpleNamespace(get_strings_from_hash=lambda *a, **k: calls.append(a))
        cancel = threading.Event()
        cancel.set()
        lock = threading.Lock()
        lock.acquire()
        self.scanner.worker(object(), cancel, self.base, self.normal, [0x7C0DFCAA], lock)
        self.assertEqual(calls, [])
        self.assertFalse(lock.locked())

    def test_hunt_context_has_no_ctree_objects(self):
        self.scanner.current = lambda quiet=False: types.SimpleNamespace(entry_ea=0x1000)
        self.scanner.collect = lambda cfunc: self.base.keys
        context = self.scanner.capture_context()
        self.assertEqual(context[1:], (0x1000, 'fixture', 1, self.base.keys))
        self.assertIs(context[0], self.scanner._instance_token)

    def test_stale_hunt_context_does_not_open_form(self):
        context = (self.scanner._instance_token, 0x1000, 'fixture', 1, self.base.keys)
        for stale in ((object(),) + context[1:], context[:3] + (0, context[4]),
                      context[:2] + ('other',) + context[3:]):
            with patch.object(pc, 'ScanForm') as form:
                self.scanner.open_dialog(stale)
                form.assert_not_called()

    def test_cancel_scan_options_does_not_start_scan(self):
        self.scanner.backend = types.SimpleNamespace(HASHDB_ALGORITHM='ror13_add', HASHDB_ALGORITHM_SIZE=32)
        context = (self.scanner._instance_token, 0x1000, 'fixture', 1, self.base.keys)
        with patch.object(pc, 'ScanForm') as form, patch.object(self.scanner, 'scan') as scan:
            form.return_value.ask.return_value = None
            self.scanner.open_dialog(context)
            form.assert_called_once_with(self.scanner, 0x1000, self.base.keys)
            scan.assert_not_called()

    def test_hunt_algorithm_missing_from_catalog_is_selected(self):
        self.scanner.backend = types.SimpleNamespace(HASHDB_ALGORITHM='new_custom_hash', HASHDB_ALGORITHM_SIZE=64)
        self.scanner.last_algorithm = 'ror13_add'
        context = (self.scanner._instance_token, 0x1000, 'fixture', 1, self.base.keys)
        with patch.object(pc, 'ScanForm') as form:
            form.return_value.ask.return_value = None
            self.scanner.open_dialog(context)
        self.assertEqual(self.scanner.last_algorithm, 'new_custom_hash')
        self.assertIn(('new_custom_hash', 64), self.scanner.algorithms)


class HuntIntegrationTests(unittest.TestCase):
    """Exercise the actual Hunt functions without importing unrelated IDA code."""
    def setUp(self):
        tree = ast.parse((ROOT / 'hashdb.py').read_text(encoding='utf-8'))
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in ('hunt_algorithm_done', 'hunt_algorithm_run')]
        self.lock = threading.Lock()
        self.lock.acquire()
        self.context = ('scanner', 0x1000, 'fixture', 1, ((32, 123),))
        self.offered = []
        scanner = types.SimpleNamespace(capture_context=lambda: self.context,
                                       open_dialog=lambda ctx: self.offered.append((ctx, self.lock.locked())))
        self.worker = None

        def worker(**kwargs):
            self.worker = types.SimpleNamespace(**kwargs, start=lambda: None)
            return self.worker

        self.env = dict(Union=Union, logging=logging, functools=functools,
                        HASHDB_REQUEST_LOCK=self.lock, HASHDB_USE_XOR=False,
                        HASHDB_PLUGIN_OBJECT=types.SimpleNamespace(_pseudocode=scanner),
                        idaapi=types.SimpleNamespace(msg=lambda text: None),
                        ida_kernwin=types.SimpleNamespace(execute_sync=lambda fn, flags: fn(), MFF_FAST=0),
                        hunt_result_form_t=types.SimpleNamespace(show=lambda response: True),
                        parse_highlighted_value=lambda: 123, HashDBError=ValueError,
                        hunt_algorithm_request=lambda *args: None, hunt_algorithm_error=lambda: None,
                        Worker=worker)
        exec(compile(ast.Module(body=functions, type_ignores=[]), 'hashdb.py', 'exec'), self.env)

    def test_selection_offers_origin_after_releasing_lock(self):
        self.assertFalse(self.env['hunt_algorithm_run']())
        self.worker.done_callback([['ror13_add', 32]])
        self.assertEqual(self.offered, [(self.context, False)])
        self.assertFalse(self.lock.locked())

    def test_hunt_cancel_or_no_result_does_not_offer_scan(self):
        for result in (None, []):
            if not self.lock.locked():
                self.lock.acquire()
            self.env['hunt_result_form_t'].show = lambda response: False
            self.env['hunt_algorithm_done'](result, self.context)
            self.assertFalse(self.lock.locked())
        self.assertEqual(self.offered, [])

    def test_disassembly_hunt_does_not_offer_scan(self):
        self.env['hunt_algorithm_done']([['ror13_add', 32]])
        self.assertEqual(self.offered, [])
        self.assertFalse(self.lock.locked())

    def test_followup_failure_cannot_trigger_double_release(self):
        def fail(ctx):
            raise RuntimeError('UI unavailable')
        self.env['HASHDB_PLUGIN_OBJECT']._pseudocode.open_dialog = fail
        with self.assertLogs(level='ERROR'):
            self.env['hunt_algorithm_done']([['ror13_add', 32]], self.context)
        self.assertFalse(self.lock.locked())


if __name__ == '__main__':
    unittest.main()
