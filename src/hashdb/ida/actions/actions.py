# IDAPython
import ida_kernwin

# HashDB
from ...utilities.logging import info, warning
from .action import Action
from .separator import Separator
from .lookup_hash import LookupHash
from .hunt_hash_algorithm import HuntHashAlgorithm
from .scan_hashes import ScanHashes
from ...settings.plugin import PLUGIN_NAME


class Actions:
    """
    Dedicated class for initializing and handling
      IDA popup menu actions.
    """
    action_items: list[Action]

    def setup(self):
        """Register all actions."""
        # Setup the actions
        self.action_items = []
        self.action_items.append(LookupHash())
        self.action_items.append(HuntHashAlgorithm())
        self.action_items.append(ScanHashes())

        # Register the actions
        action: Action
        for action in self.action_items:
            if type(action) is not Separator and not action.register():
                warning(f"Failed to register action: {action.name}")

    def attach_to_popup(self, widget, popup_handle):
        """
        Attaches all the action instances to the widget.
        @param widget: TWidget*
        @param popup_handle: TPopupMenu*
        """
        # Check for the correct widget type
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type is not ida_kernwin.BWN_DISASM and widget_type is not ida_kernwin.BWN_PSEUDOCODE:
            return

        action: Action
        for action in self.action_items:
            ida_kernwin.attach_action_to_popup(
                widget, popup_handle,
                action.name, f"{PLUGIN_NAME}/",  # popuppath
                ida_kernwin.SETMENU_APP          # append
            )

    def cleanup(self):
        """Cleanup all actions (unregister and free their icons)."""
        action: Action
        for action in self.action_items:
            # Do not unregister separators
            if isinstance(action, Separator):
                continue

            if not action.unregister():
                warning(f"Failed to unregister action: {action.name}")
            action.free_icon()

    # noinspection PyUnusedLocal,PyMethodMayBeStatic
    def __on_hunt_hash_algo(self, context=None):
        info("__on_hunt_hash_algo")

    # noinspection PyUnusedLocal,PyMethodMayBeStatic
    def __on_scan_hashes(self, context=None):
        info("__on_scan_hashes")
