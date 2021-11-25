# HashDB
from ida.hooks.ui import UiHooks
from utilities.hexrays import is_hexrays_decompiler_available
if is_hexrays_decompiler_available():
    from ida.hooks.hexrays import HexRaysHooks


class HashDBCore:
    loaded: bool = False  # has the `ready_to_run` event been called?
    __ui_hooks: UiHooks
    if is_hexrays_decompiler_available():
        __hexrays_hooks: HexRaysHooks

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
            self.__ui_hooks.hook()

        # Is the Hex-Rays decompiler available?
        if is_hexrays_decompiler_available():
            self.__hexrays_hooks = HexRaysHooks()

        # Assume the plugin is being reloaded, load directly
        if not initial_setup:
            self.load()

    def load(self) -> None:
        """
        Registers the proper UI hooks (e.g. Hex-Rays)
         and handles the setup.
        """
        # Remove hooks
        self.__ui_hooks.unhook()

        # Dereference the self.__hooks object, it's no
        #  longer required
        del self.__ui_hooks

        # Is the Hex-Rays decompiler available?
        if is_hexrays_decompiler_available():
            # TODO (printup): implement hex-rays hooks
            pass

        # Signal that loading was successful
        self.loaded = True

    def unload(self) -> None:
        pass

    def run_tests_cli(self) -> None:
        pass

    def run_tests_ida(self) -> None:
        pass
