# System packages/modules
import zlib
import base64
from typing import Callable

# IDAPython
import ida_kernwin

# HashDB
from ...utilities.logging import info
from action import Action
from ...config import PLUGIN_NAME, PLUGIN_HOTKEYS
from ..ui.icons import LOOKUP_HASH_ICON_COMPRESSED, HUNT_HASH_ICON_COMPRESSED, SCAN_HASHES_ICON_COMPRESSED


def load_custom_icon(compressed_data: bytes, image_format: str = "png") -> int:
    """
    Load custom icons from embedded data (bytes).
    @param compressed_data: compressed data to load
    @param image_format: image format
    @return: a unique icon id (int)
    """
    data = zlib.decompress(base64.standard_b64decode(compressed_data))
    return ida_kernwin.load_custom_icon(data=data, format=image_format)


class LookupHash(Action):
    def __init__(self, callback: Callable):
        self.icon = load_custom_icon(LOOKUP_HASH_ICON_COMPRESSED)
        super().__init__(name="lookup_hash",
                         label=f"{PLUGIN_NAME} Lookup",
                         callback=callback,
                         shortcut=PLUGIN_HOTKEYS["lookup_hash"],
                         tooltip="Try to lookup a hash",
                         icon=self.icon)
        assert self.register(), "Failed to register the lookup_hash action descriptor."


class HuntHashAlgorithm(Action):
    def __init__(self, callback: Callable):
        self.icon = load_custom_icon(HUNT_HASH_ICON_COMPRESSED)
        super().__init__(name="hunt_hash_algo",
                         label=f"{PLUGIN_NAME} Hunt Algorithm",
                         callback=callback,
                         shortcut=PLUGIN_HOTKEYS["hunt_hash_algo"],
                         tooltip="Try to find the hashing algorithm used for this hash",
                         icon=self.icon)
        assert self.register(), "Failed to register the hunt_hash_algo action descriptor."


class ScanHashes(Action):
    def __init__(self, callback: Callable):
        self.icon = load_custom_icon(SCAN_HASHES_ICON_COMPRESSED)
        super().__init__(name="scan_hashes",
                         label=f"{PLUGIN_NAME} Scan Hashes",
                         callback=callback,
                         shortcut=PLUGIN_HOTKEYS["scan_hashes"],
                         tooltip="Try to lookup multiple hashes at once",
                         icon=self.icon)
        assert self.register(), "Failed to register the scan_hashes action descriptor."


class Actions:
    """
    Dedicated class for initializing and handling
      IDA popup menu actions.
    """
    lookup_hash: LookupHash
    hunt_hash_algo: HuntHashAlgorithm
    scan_hashes: ScanHashes

    def setup(self) -> None:
        """
        Register all actions.
        """
        self.lookup_hash = LookupHash(callback=self.__on_lookup_hash)
        self.hunt_hash_algo = HuntHashAlgorithm(callback=self.__on_hunt_hash_algo)
        self.scan_hashes = ScanHashes(callback=self.__on_scan_hashes)

    def attach_to_popup(self, widget, popup_handle) -> None:
        """
        Attaches all the action instances to the widget.
        @param widget: TWidget*
        @param popup_handle: TPopupMenu*
        """
        action: Action
        for action in (self.lookup_hash, self.hunt_hash_algo, self.scan_hashes):
            ida_kernwin.attach_action_to_popup(
                widget, popup_handle,
                action.name,
                None,
                ida_kernwin.SETMENU_APP  # append
            )

    def cleanup(self) -> None:
        """
        Cleanup all actions (unregister and free their icons)
        """
        action: Action
        for action in (self.lookup_hash, self.hunt_hash_algo, self.scan_hashes):
            action.unregister()
            action.free_icon()

    # --------------------------------------------------------------------------
    # Action callbacks
    # --------------------------------------------------------------------------
    # noinspection PyUnusedLocal,PyMethodMayBeStatic
    def __on_lookup_hash(self, context=None):
        info("__on_lookup_hash")

    # noinspection PyUnusedLocal,PyMethodMayBeStatic
    def __on_hunt_hash_algo(self, context=None):
        info("__on_hunt_hash_algo")

    # noinspection PyUnusedLocal,PyMethodMayBeStatic
    def __on_scan_hashes(self, context=None):
        info("__on_scan_hashes")
