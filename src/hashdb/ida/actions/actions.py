# System packages/modules
import zlib
import base64
from typing import Callable

# IDAPython
import ida_kernwin

# HashDB
from ...utilities.logging import info, warning
from .action import Action
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


class Separator(Action):
    def __init__(self):
        super().__init__(name="-", label="", callback=lambda x: None, name_prefix=False)


class LookupHash(Action):
    def __init__(self, callback: Callable):
        self.icon = load_custom_icon(LOOKUP_HASH_ICON_COMPRESSED)
        super().__init__(name="lookup_hash",
                         label="Lookup Hash",
                         callback=callback,
                         shortcut=PLUGIN_HOTKEYS["lookup_hash"],
                         tooltip="Try to lookup a hash",
                         icon=self.icon)


class HuntHashAlgorithm(Action):
    def __init__(self, callback: Callable):
        self.icon = load_custom_icon(HUNT_HASH_ICON_COMPRESSED)
        super().__init__(name="hunt_hash_algo",
                         label="Hunt Algorithm",
                         callback=callback,
                         shortcut=PLUGIN_HOTKEYS["hunt_hash_algo"],
                         tooltip="Try to find the hashing algorithm used for this hash",
                         icon=self.icon)


class ScanHashes(Action):
    def __init__(self, callback: Callable):
        self.icon = load_custom_icon(SCAN_HASHES_ICON_COMPRESSED)
        super().__init__(name="scan_hashes",
                         label="Scan Hashes",
                         callback=callback,
                         shortcut=PLUGIN_HOTKEYS["scan_hashes"],
                         tooltip="Try to lookup multiple hashes at once",
                         icon=self.icon)


class Actions:
    """
    Dedicated class for initializing and handling
      IDA popup menu actions.
    """
    action_items: list[Action]

    def setup(self) -> None:
        """
        Register all actions.
        """
        # Setup the actions
        self.action_items = []
        self.action_items.append(LookupHash(callback=self.__on_lookup_hash))
        self.action_items.append(HuntHashAlgorithm(callback=self.__on_hunt_hash_algo))
        self.action_items.append(ScanHashes(callback=self.__on_scan_hashes))

        # Register the actions
        action: Action
        for action in self.action_items:
            if type(action) is not Separator and not action.register():
                warning(f"Failed to register action: {action.name}")

    def attach_to_popup(self, widget, popup_handle) -> None:
        """
        Attaches all the action instances to the widget.
        @param widget: TWidget*
        @param popup_handle: TPopupMenu*
        """
        action: Action
        for action in self.action_items:
            ida_kernwin.attach_action_to_popup(
                widget, popup_handle,
                action.name, f"{PLUGIN_NAME}/",  # popuppath
                ida_kernwin.SETMENU_APP          # append
            )

    def cleanup(self) -> None:
        """
        Cleanup all actions (unregister and free their icons)
        """
        action: Action
        for action in self.action_items:
            if type(action) is not Separator and not action.unregister():  # Do not unregister separators
                warning(f"Failed to unregister action: {action.name}")
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
