# System packages/modules
import zlib
import base64
from typing import Callable

# IDAPython
import ida_kernwin

# HashDB
from .handler import Handler
from ...settings.plugin import PLUGIN_NAME, PLUGIN_ACTIONS_PREFIX


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
                 name_prefix: bool = True,
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
        action_name = f"{PLUGIN_ACTIONS_PREFIX}:{name}" if name_prefix else name
        self.descriptor = ida_kernwin.action_desc_t(
            action_name, label, Handler(callback),
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
        return ida_kernwin.unregister_action(self.name)

    def free_icon(self):
        """Free an icon instance, if it exists."""
        if self.icon != -1:
            ida_kernwin.free_custom_icon(self.icon)
            self.icon = -1

    def attach_to_menu(self) -> bool:
        return ida_kernwin.attach_action_to_menu(
            f"Edit/Plugins/{PLUGIN_NAME}/{self.label}",  # menupath
            self.name,                                   # name
            ida_kernwin.SETMENU_APP                      # append
        )

    def detach_from_menu(self) -> bool:
        return ida_kernwin.detach_action_from_menu(
            f"Edit/Plugins/{PLUGIN_NAME}/{self.label}",  # menupath
            self.name                                    # name
        )

    # noinspection PyPropertyAccess
    @property
    def name(self) -> str:
        return self.descriptor.name

    # noinspection PyPropertyAccess
    @property
    def label(self) -> str:
        return self.descriptor.label

    # noinspection PyPropertyAccess
    @property
    def shortcut(self) -> str:
        return self.descriptor.shortcut

    # noinspection PyPropertyAccess
    @property
    def tooltip(self) -> str:
        return self.descriptor.tooltip

    # noinspection PyPropertyAccess
    @property
    def flags(self) -> str:
        return self.descriptor.flags


def load_custom_icon(compressed_data: bytes, image_format: str = "png") -> int:
    """
    Load custom icons from embedded data (bytes).
    @param compressed_data: compressed data to load
    @param image_format: image format
    @return: a unique icon id (int)
    """
    data = zlib.decompress(base64.standard_b64decode(compressed_data))
    return ida_kernwin.load_custom_icon(data=data, format=image_format)
