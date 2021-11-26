# System packages/modules
from typing import Callable

# IDAPython
import ida_kernwin

# HashDB
from handler import Handler
from ...config import PLUGIN_ACTIONS_PREFIX


class Action:
    """
    An Action class describes the attributes of an action
      associated to an `action_desc_t`.

    A prefix is automatically prepended to the name.
    It also manages its lifetime (registration, deletion).
    """
    icon: int = -1
    descriptor: ida_kernwin.action_desc_t

    def __init__(self, name: str, label: str, callback: Callable,
                 shortcut: str = None, tooltip: str = None,
                 icon: int = -1, flags: int = 0):
        """
        Initializes its descriptor object with the following arguments:
        @param name:     unique id/name
        @param label:    text/label shown in the popup menu
        @param callback: a callback that's invoked when the user clicks on the menu
        @param shortcut: optional shortcut (X-Y-Z) format, separated by hyphens
        @param tooltip:  optional tooltip
        @param icon:     optional icon (ida_kernwin.load_custom_icon)
        @param flags:    optional flags
        """
        self.descriptor = ida_kernwin.action_desc_t(
            f"{PLUGIN_ACTIONS_PREFIX}:{name}", label, Handler(callback),
            shortcut, tooltip, icon, flags)

    def register(self) -> bool:
        """
        Register the action descriptor.
        @return: True if registered successfully,
                 False if it failed
        """
        return ida_kernwin.register_action(self.descriptor)

    def unregister(self) -> bool:
        """
        Delete the action descriptor.
        @return: True if unregistered successfully,
                 False if it failed
        """
        return ida_kernwin.unregister_action(self.descriptor)

    def free_icon(self) -> None:
        """
        Free an icon instance, if it exists
        """
        if self.icon != -1:
            ida_kernwin.free_custom_icon(self.icon)

    # noinspection PyPropertyAccess
    @property
    def name(self) -> str:
        return self.descriptor.name
