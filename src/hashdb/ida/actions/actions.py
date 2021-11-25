# System packages/modules
from typing import Callable

# HashDB
from action import Action
from ...config import PLUGIN_NAME, PLUGIN_HOTKEYS
from ..ui.icons import LOOKUP_HASH_ICON, HUNT_HASH_ICON, SCAN_HASHES_ICON


class LookupHash(Action):
    def __init__(self, callback: Callable):
        super().__init__(name="lookup_hash",
                         label=f"{PLUGIN_NAME} Lookup",
                         callback=callback,
                         shortcut=PLUGIN_HOTKEYS["lookup_hash"],
                         tooltip="Try to lookup a hash",
                         icon=LOOKUP_HASH_ICON)
        assert self.register(), "Failed to register the lookup_hash action descriptor."


class HuntHashAlgorithm(Action):
    def __init__(self, callback: Callable):
        super().__init__(name="hunt_hash_algo",
                         label=f"{PLUGIN_NAME} Hunt Algorithm",
                         callback=callback,
                         shortcut=PLUGIN_HOTKEYS["hunt_hash_algo"],
                         tooltip="Try to find the hashing algorithm used for this hash",
                         icon=HUNT_HASH_ICON)
        assert self.register(), "Failed to register the hunt_hash_algo action descriptor."


class ScanHashes(Action):
    def __init__(self, callback: Callable):
        super().__init__(name="scan_hashes",
                         label=f"{PLUGIN_NAME} Scan Hashes",
                         callback=callback,
                         shortcut=PLUGIN_HOTKEYS["scan_hashes"],
                         tooltip="Try to lookup multiple hashes at once",
                         icon=SCAN_HASHES_ICON)
        assert self.register(), "Failed to register the scan_hashes action descriptor."


class Actions:
    """
    Dedicated class for initializing and handling
      IDA popup menu actions.
    """
    lookup_hash: LookupHash
    hunt_hash: HuntHashAlgorithm
    scan_hashes: ScanHashes
