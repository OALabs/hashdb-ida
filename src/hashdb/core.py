# HashDB
from .settings.plugin import AUTHOR, VERSION_STRING
from .ida.hooks.ui import UiHooks
from .utilities.hexrays import is_hexrays_module_available, is_hexrays_decompiler_available
if is_hexrays_module_available():  # Conditionally import, if the Hex-Rays decompiler is available
    from .ida.hooks.hexrays import HexRaysHooks
from .ida.actions.actions import Actions
from .utilities.logging import info


class HashDBCore:
    loaded: bool = False  # has the `ready_to_run` event been called?
    __ui_hooks: UiHooks
    if is_hexrays_module_available():
        __hexrays_hooks: HexRaysHooks
    __actions: Actions

    def __init__(self, initial_setup: bool):
        """
        Initializes (or queues initialization for) the plugin.
        @param initial_setup: if this is within the context of
                the initial plugin setup, wait until the UI is
                ready before fully loading all of the elements
        """
        # Is this the first time this method was called?
        self.__ui_hooks = UiHooks()
        if initial_setup:
            self.__ui_hooks.ready_to_run = self.load
        # Active the hooks
        self.__ui_hooks.hook()

        # Is the Hex-Rays decompiler available?
        if is_hexrays_decompiler_available():
            self.__hexrays_hooks = HexRaysHooks()

        # Create an Actions instance
        self.__actions = Actions()

        # Assume the plugin is being reloaded, load directly
        if not initial_setup:
            self.load()

    def load(self):
        """
        Registers the UI hooks (UI, Hex-Rays)
          and handles the setup.
        """
        # Initialize the actions and their icons
        self.__actions.setup()

        # Register the UI action hooks
        self.__register_ui_hooks()

        # If the Hex-Rays decompiler available,
        #  register Hex-Rays specific hooks:
        if is_hexrays_decompiler_available():
            self.__register_hexrays_hooks()

        # Mark the Core as loaded
        self.loaded = True

        # Tell the user that we loaded successfully
        info(f"Plugin version v{VERSION_STRING} by {AUTHOR} loaded successfully.")

    def unload(self):
        """
        Unhooks the UI hooks, and cleans up
          any relevant code (e.g. actions)
        """
        # If the plugin isn't loaded, abort:
        if not self.loaded:
            return

        # If the Hex-Rays decompiler available,
        #  unhook and dereference the Hex-Rays
        #  specific hooks:
        if is_hexrays_decompiler_available():
            self.__remove_hexrays_hooks()
            del self.__hexrays_hooks

        # Unhook and dereference the UI hooks
        self.__remove_ui_hooks()
        del self.__ui_hooks

        # Cleanup and dereference the Actions instance
        self.__actions.cleanup()
        del self.__actions

        # Mark the Core as unloaded
        self.loaded = False

    # --------------------------------------------------------------------------
    # UI hooks
    # --------------------------------------------------------------------------
    def __register_ui_hooks(self):
        """
        Register the UI hooks.
        """
        self.__ui_hooks.populating_widget_popup = self.__on_ui_populating_widget_popup

    def __remove_ui_hooks(self):
        """
        Remove all UI hooks.
        """
        self.__ui_hooks.unhook()

    # noinspection PyUnusedLocal
    def __on_ui_populating_widget_popup(self, widget, popup_handle, context=None):
        """
        Invoked when a popup event is triggered. This callback allows us
          to add new menu entries into the context menu.
        @param widget: TWidget*
        @param popup_handle: TPopupMenu*
        @return: 1 is the event was handled (decompiler manual)
        """
        self.__actions.attach_to_popup(widget, popup_handle)
        return 0

    # Hex-Rays hooks
    # ida_hexrays.html#ida_hexrays.Hexrays_Hooks.populating_popup
    def __register_hexrays_hooks(self):
        """
        Register the Hex-Rays hooks.
        """
        self.__hexrays_hooks.populating_popup = self.__on_hexrays_populating_popup
        self.__hexrays_hooks.hook()

    def __remove_hexrays_hooks(self):
        """
        Remove all Hex-Rays hooks.
        """
        self.__hexrays_hooks.unhook()

    # noinspection PyUnusedLocal,PyMethodMayBeStatic
    def __on_hexrays_populating_popup(self, widget, popup_handle, vu) -> int:
        """
        Invoked when a popup event is triggered. This callback allows us
          to add new menu entries into the context menu.
        @param widget: TWidget*
        @param popup_handle: TPopupMenu*
        @param vu: vdui_t*
        @return: 1 is the event was handled (decompiler manual)
        """
        self.__actions.attach_to_popup(widget, popup_handle)
        return 0

    # Unit testing
    def run_tests_cli(self):
        pass

    def run_tests_ida(self):
        pass
