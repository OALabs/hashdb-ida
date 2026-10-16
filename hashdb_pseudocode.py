"""Manual HashDB scans of the current ctree, with optional scoped suffixes.

All IDA objects stay on the UI thread. Workers receive primitive snapshots.
No requests are made by the printing hooks or by plugin initialization.
"""
import importlib.util
import json
import pathlib
import queue
import threading
import traceback
from dataclasses import dataclass

import ida_hexrays as hx
import ida_kernwin as kw
import ida_nalt


ROOT = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("_hashdb_scoped_renderer", ROOT / "hashdb_inlay.py")
renderer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(renderer)
SHORT_NAMES = {"ror13_add": "ror13"}  # Explicit alias, not a lossy truncation.


def normalize_for_algorithm(bits, value, algorithm_bits):
    """Accept exact unsigned or sign-extended values; do not truncate addresses."""
    mask = (1 << algorithm_bits) - 1
    if value <= mask:
        return value
    if bits > algorithm_bits:
        low = value & mask
        high = value >> algorithm_bits
        if low & (1 << (algorithm_bits - 1)) and high == (1 << (bits - algorithm_bits)) - 1:
            return low
    return None


def candidates_from_response(response, preferred_dll=""):
    """Keep collisions/module ambiguity; a preference only selects real modules."""
    candidates = set()
    preferred = preferred_dll.lower().removesuffix(".dll")
    for hit in response.get("hashes", []):
        item = hit.get("string", {})
        if item.get("is_api", False):
            name = item.get("api") or item.get("string")
            if not name:
                continue
            modules = sorted(set(item.get("modules") or ["?"]))
            selected = [dll for dll in modules if dll.lower().removesuffix(".dll") == preferred]
            for dll in selected or modules:
                candidates.add((str(dll), str(name)))
        elif item.get("string"):
            candidates.add(("", str(item["string"])))
    return sorted(candidates)


def format_candidates(algorithm, candidates):
    short = SHORT_NAMES.get(algorithm, algorithm)
    targets = ["%s!%s" % pair if pair[0] else json.dumps(pair[1]) for pair in candidates]
    return "%s: %s" % (short, " | ".join(targets)) if targets else None


@dataclass(frozen=True)
class ScanSpec:
    entry_ea: int
    database: str
    epoch: int
    algorithm: str
    algorithm_bits: int
    xor: int
    api_url: str
    preferred_dll: str
    apply_hints: bool
    keys: tuple
    max_requests: int = 500


class ScopedRenderer(renderer.HintRenderer):
    def __init__(self):
        super().__init__()
        self.by_function = {}
        self.enabled = False

    def decorate(self, cfunc):
        previous = self.hints
        self.hints = self.by_function.get(cfunc.entry_ea, {})
        try:
            super().decorate(cfunc)
        finally:
            self.hints = previous


class ScanForm(kw.Form):
    def __init__(self, owner, entry_ea, keys):
        self.owner = owner
        self.entry_ea = entry_ea
        self.keys = keys
        self.rows = list(owner.algorithms)
        self.alive = False
        F = kw.Form
        chosen = owner.last_algorithm
        index = next((i for i, row in enumerate(self.rows) if row[0] == chosen), 0)
        super().__init__(
            "BUTTON YES* Resolve\nBUTTON CANCEL Cancel\nHashDB - Resolve pseudocode immediates\n\n"
            "Scans numeric expressions in the entire current function.\n"
            "Only Resolve starts hash lookups. Existing enums/types are preserved.\n\n"
            "<Algorithm:{algorithm}> <Refresh algorithms:{refresh_algorithms}>\n"
            "<API URL:{server}>\n<Prefer DLL (optional):{preferred}>\n"
            "<XOR (hex):{xor}>\n<Maximum unique requests:{limit}>\n"
            "<Apply inline hints:{inline}>{options}>\n"
            "\nSuffix: algorithm: dll!function (plain muted text)\n",
            {"algorithm": F.DropdownListControl(
                items=["%s (%d-bit)" % row for row in self.rows], readonly=True, selval=index),
             "refresh_algorithms": F.ButtonInput(self.refresh_catalog),
             "server": F.StringInput(value=owner.backend.HASHDB_API_URL),
             "preferred": F.StringInput(value=owner.preferred_dll),
             "xor": F.NumericInput(tp=F.FT_RAWHEX, value=owner.backend.HASHDB_XOR_VALUE
                                   if owner.backend.HASHDB_USE_XOR else 0),
             "limit": F.NumericInput(tp=F.FT_DEC, value=500),
             "options": F.ChkGroupControl(("inline",), value=1 if owner.inline_default else 0)})

    def refresh_catalog(self, code=0):
        server = self.GetControlValue(self.server).strip().rstrip("/")
        self.owner.refresh_catalog(server, self)

    def update_catalog(self, rows):
        if not self.alive:
            return
        old_row = self.rows[self.GetControlValue(self.algorithm)]
        old = old_row[0]
        if not any(name == old for name, bits in rows):
            rows = sorted(rows + [old_row])
        self.rows = rows
        self.algorithm.set_items(["%s (%d-bit)" % row for row in rows])
        self.RefreshField(self.algorithm)
        self.SetControlValue(self.algorithm, next((i for i, row in enumerate(rows) if row[0] == old), 0))

    def ask(self):
        self.Compile()
        self.alive = True
        try:
            if self.Execute() != 1:
                return None
            algorithm, bits = self.rows[self.algorithm.value]
            return ScanSpec(
                self.entry_ea, self.owner.database, self.owner.epoch, algorithm, bits,
                int(self.xor.value), self.server.value.strip().rstrip("/"),
                self.preferred.value.strip(), bool(self.options.value & 1), tuple(self.keys),
                int(self.limit.value))
        finally:
            self.alive = False
            self.Free()


class Results(kw.Choose):
    def __init__(self, owner, spec, rows):
        self.owner, self.spec, self.rows = owner, spec, rows
        super().__init__("HashDB pseudocode results - %X" % spec.entry_ea,
                         [["Constant", 18], ["Algorithm", 20], ["Result", 70]])

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        return self.rows[n]


class Action(kw.action_handler_t):
    def __init__(self, callback, pseudocode_only=True):
        super().__init__()
        self.callback, self.pseudocode_only = callback, pseudocode_only

    def activate(self, ctx):
        try:
            self.callback()
        except Exception:
            kw.msg("HashDB: " + traceback.format_exc())
        return 1

    def update(self, ctx):
        if not self.pseudocode_only:
            return kw.AST_ENABLE_ALWAYS
        return kw.AST_ENABLE_FOR_WIDGET if ctx.widget_type == kw.BWN_PSEUDOCODE else kw.AST_DISABLE_FOR_WIDGET


class UIHooks(kw.UI_Hooks):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def finish_populating_widget_popup(self, widget, popup):
        if kw.get_widget_type(widget) == kw.BWN_PSEUDOCODE:
            for name in self.owner.context_actions:
                kw.attach_action_to_popup(widget, popup, name, "HashDB/")

    def database_closed(self):
        self.owner.invalidate()


class PseudocodeScanner:
    def __init__(self, backend):
        self.backend = backend
        self.database = ida_nalt.get_input_file_path()
        self.epoch = 0
        self.alive = True
        self.events = queue.Queue()
        self.job = None
        self.cancel_event = None
        self.last_result = None
        self.last_error = None
        self.choosers = []
        self.preferred_dll = ""
        self._instance_token = object()
        self.inline_default = True
        self.algorithms = [("ror13_add", 32)]
        try:
            catalog = json.loads((ROOT / "hashdb_algorithms.json").read_text(encoding="utf-8-sig"))
            self.algorithms = sorted((a["algorithm"], 64 if a["type"] == "unsigned_long" else 32)
                                     for a in catalog["algorithms"] if a["type"] in ("unsigned_int", "unsigned_long"))
        except (OSError, ValueError, KeyError):
            pass
        self.last_algorithm = backend.HASHDB_ALGORITHM or "ror13_add"
        self.renderer = ScopedRenderer()
        if not self.renderer._hooks.hook():
            raise RuntimeError("Could not hook Hex-Rays")
        self.renderer._running = True
        self.actions = []
        self.context_actions = []
        self.hooks = None
        self.timer = None
        try:
            self.register("hashdb:toggle_pseudocode_hints", "HashDB: Show/hide pseudocode hints", self.renderer.toggle)
            self.register("hashdb:clear_pseudocode_hints", "Clear hints in this function", self.clear_current)
            self.register("hashdb:cancel_pseudocode_scan", "Cancel pseudocode scan", self.cancel)
            self.hooks = UIHooks(self)
            self.hooks.hook()
            self.timer = kw.register_timer(100, self.poll)
            if self.timer is None:
                raise RuntimeError("Could not register scan completion timer")
        except Exception:
            self.stop()
            raise

    def register(self, name, title, callback):
        handler = Action(callback)
        if not kw.register_action(kw.action_desc_t(name, title, handler)):
            raise RuntimeError("Action already registered: " + name)
        self.actions.append((name, handler))
        if name == "hashdb:toggle_pseudocode_hints":
            kw.attach_action_to_menu("Edit/Plugins/", name, kw.SETMENU_APP)
        self.context_actions.append(name)

    def current(self, quiet=False):
        widget = kw.get_current_widget()
        if not widget or kw.get_widget_type(widget) != kw.BWN_PSEUDOCODE:
            if not quiet:
                kw.msg("HashDB: Focus the pseudocode function to scan.\n")
            return None
        vu = hx.get_widget_vdui(widget)
        if not vu or not vu.cfunc:
            return None
        return vu.cfunc

    @staticmethod
    def collect(cfunc):
        cfunc.get_pseudocode()
        return tuple(sorted({renderer._number_key(item.cexpr) for item in cfunc.treeitems
                             if item.op == hx.cot_num} - {None}))

    def capture_context(self):
        """Snapshot the Hunt origin on the UI thread, without retaining ctree."""
        cfunc = self.current(quiet=True) if self.alive else None
        if cfunc is None:
            return None
        return (self._instance_token, int(cfunc.entry_ea), self.database,
                self.epoch, self.collect(cfunc))

    def open_dialog(self, context=None):
        if not self.alive:
            kw.msg("HashDB: The database changed. Reopen the database to restart the scanner.\n")
            return
        if self.job is not None:
            kw.msg("HashDB: A pseudocode scan is running; wait or cancel it first.\n")
            return
        context = context if context is not None else self.capture_context()
        if context is None:
            return
        token, entry_ea, database, epoch, keys = context
        if token is not self._instance_token or database != self.database or epoch != self.epoch:
            return
        # Every Hunt selection wins, even if it repeats the previous algorithm.
        # A newly added/custom algorithm may not be in the bundled catalog yet.
        selected = self.backend.HASHDB_ALGORITHM
        if selected:
            self.last_algorithm = selected
            bits = int(self.backend.HASHDB_ALGORITHM_SIZE)
            if bits in (32, 64):
                self.algorithms = sorted([(name, width) for name, width in self.algorithms
                                          if name != selected] + [(selected, bits)])
        if not keys:
            kw.msg("HashDB: No numeric expressions in this pseudocode function.\n")
            return
        spec = ScanForm(self, entry_ea, keys).ask()
        if spec is not None:
            self.scan(spec)

    def scan(self, spec):
        """Manual entry point, also usable from the test console with a snapshot."""
        if not self.alive or self.job is not None:
            raise RuntimeError("Scanner is unloaded or already busy")
        if spec.database != self.database or spec.epoch != self.epoch:
            raise ValueError("The database changed; invoke the scan again")
        if spec.algorithm_bits not in (32, 64) or not 0 <= spec.xor < 1 << spec.algorithm_bits:
            raise ValueError("Invalid algorithm width or XOR value")
        if not spec.api_url.startswith(("http://", "https://")):
            raise ValueError("API URL must start with http:// or https://")
        normalized = {key: normalize_for_algorithm(*key, spec.algorithm_bits) for key in spec.keys}
        values = sorted({v for v in normalized.values() if v is not None})
        if not 1 <= spec.max_requests <= 10000 or len(values) > spec.max_requests:
            raise ValueError("%d unique values exceed the request limit (%d); raise the limit to scan all" % (len(values), spec.max_requests))
        request_lock = self.backend.HASHDB_REQUEST_LOCK
        if not request_lock.acquire(blocking=False):
            raise RuntimeError("Another HashDB request is running; wait or cancel it first")
        self.last_algorithm, self.preferred_dll = spec.algorithm, spec.preferred_dll
        self.inline_default = spec.apply_hints
        self.last_error = None
        self.last_result = None
        self.cancel_event = threading.Event()
        self.job = object()
        token, cancel = self.job, self.cancel_event
        kw.msg("HashDB: Manually scanning %d unique values in function %X with %s; %d out-of-range expressions skipped.\n"
               % (len(values), spec.entry_ea, spec.algorithm, sum(v is None for v in normalized.values())))
        try:
            threading.Thread(target=self.worker, args=(token, cancel, spec, normalized, values, request_lock),
                             daemon=True, name="HashDB-pseudocode-scan").start()
        except Exception:
            self.job = None
            self.cancel_event = None
            request_lock.release()
            raise

    def worker(self, token, cancel, spec, normalized, values, request_lock=None):
        results = {}
        error = None
        try:
            for index, value in enumerate(values):
                if cancel.is_set() or (index and cancel.wait(0.65)):
                    break
                # Reuse HashDB-IDA's API client. Configuration is captured per job.
                response = self.backend.get_strings_from_hash(
                    spec.algorithm, value, spec.xor, spec.api_url, timeout=15)
                results[value] = candidates_from_response(response, spec.preferred_dll)
        except Exception as exc:
            error = "%s: %s" % (type(exc).__name__, exc)
        finally:
            if request_lock is not None:
                request_lock.release()
        self.events.put(("scan", token, spec, normalized, results, error, cancel.is_set()))

    def refresh_catalog(self, server, form):
        def fetch():
            try:
                rows = self.backend.get_algorithms(api_url=server, timeout=15)
                rows = sorted((name, int(bits)) for name, bits in rows if str(bits) in ("32", "64"))
                if not rows:
                    raise ValueError("The server returned no supported algorithms")
                self.events.put(("catalog", form, rows, None))
            except Exception as exc:
                self.events.put(("catalog", form, None, str(exc)))
        threading.Thread(target=fetch, daemon=True, name="HashDB-algorithms").start()

    def poll(self):
        if not self.alive:
            return -1
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "catalog":
                    _, form, rows, error = event
                    if error:
                        kw.msg("HashDB: Algorithm refresh failed: %s\n" % error)
                    else:
                        self.algorithms = rows
                        form.update_catalog(rows)
                        kw.msg("HashDB: Refreshed %d algorithms.\n" % len(rows))
                    continue
                _, token, spec, normalized, results, error, cancelled = event
                if token is not self.job:
                    continue
                self.job = None
                self.cancel_event = None
                if spec.epoch != self.epoch or spec.database != self.database:
                    continue
                if cancelled or error:
                    self.last_error = "Cancelled" if cancelled else error
                    kw.msg("HashDB: Pseudocode scan %s; no partial hints applied.\n" % self.last_error)
                    continue
                self.publish(spec, normalized, results)
        except queue.Empty:
            pass
        except Exception:
            self.last_error = traceback.format_exc()
            kw.msg("HashDB completion error: " + self.last_error)
        return 100

    def publish(self, spec, normalized, results):
        scoped, rows = {}, []
        for key, value in normalized.items():
            if value is None:
                rows.append(["%d:0x%X" % key, spec.algorithm, "Skipped: outside algorithm width"])
                continue
            candidates = results.get(value, [])
            label = format_candidates(spec.algorithm, candidates)
            if label is not None:
                scoped[key] = renderer._clean_label(label)
            rows.append(["%d:0x%X" % key, spec.algorithm,
                         label or "No match"])
        self.renderer.by_function.pop(spec.entry_ea, None)
        if spec.apply_hints:
            self.renderer.by_function[spec.entry_ea] = scoped
            self.renderer.enabled = True
        self.renderer.refresh()
        self.last_result = {"spec": spec, "results": results, "hints": scoped, "rows": rows}
        kw.msg("HashDB: Finished %d lookups; %d expression values matched. Inline hints %s.\n"
               % (len(results), len(scoped), "applied" if spec.apply_hints else "off"))
        chooser = Results(self, spec, rows)
        self.choosers.append(chooser)
        chooser.Show(False)

    def clear_current(self):
        cfunc = self.current()
        if cfunc is not None:
            self.renderer.by_function.pop(cfunc.entry_ea, None)
            self.renderer.refresh()

    def cancel(self):
        if self.cancel_event:
            self.cancel_event.set()
            kw.msg("HashDB: Cancelling after the current request (15 second timeout).\n")

    def invalidate(self):
        self.cancel()
        self.alive = False
        self.epoch += 1
        self.job = None
        self.renderer.by_function.clear()
        self.renderer._visited.clear()
        self.database = ""

    def stop(self):
        self.cancel()
        self.alive = False
        self.job = None
        if getattr(self, "timer", None) is not None:
            kw.unregister_timer(self.timer)
            self.timer = None
        if self.hooks is not None:
            self.hooks.unhook()
        self.renderer.stop()
        for chooser in self.choosers:
            chooser.Close()
        for name, handler in self.actions:
            kw.unregister_action(name)
        self.actions.clear()
