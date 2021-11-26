# System packages/modules
import importlib

# IDAPython
import ida_idaapi
from ida_idp import IDP_INTERFACE_VERSION

# HashDB
import hashdb
from hashdb.core import HashDBCore as Core
from hashdb.config import PLUGIN_NAME
from hashdb.utilities.versions import *
from hashdb.utilities.logging import warning, debug


# noinspection PyPep8Naming
def PLUGIN_ENTRY():
    """
    Plugin entry point for IDAPython plugins.
    @return: HashDBPlugin
    """
    return HashDBPlugin()


# https://hex-rays.com/products/ida/support/sdkdoc/classplugin__t.html
# noinspection PyMethodMayBeStatic,PyUnusedLocal
class HashDBPlugin(ida_idaapi.plugin_t):
    """
    IDAPython plugin structure
    """
    # https://hex-rays.com/products/ida/support/idapython_docs/ida_idp.html#ida_idp.IDP_INTERFACE_VERSION
    version: int = IDP_INTERFACE_VERSION
    # https://hex-rays.com/products/ida/support/sdkdoc/group___p_l_u_g_i_n___i_n_i_t.html
    flags: int = ida_idaapi.PLUGIN_KEEP
    comment: str = "HashDB Lookup Service"
    help: str = ""
    wanted_name: str = PLUGIN_NAME  # hashdb.config
    wanted_hotkey: str = ""

    # Core instance variable
    __core: Core

    #--------------------------------------------------------------------------
    # Plugin function overloads
    #--------------------------------------------------------------------------
    def init(self) -> int:
        """
        Invoked when IDA is loading the plugin.
        @return: PLUGIN_KEEP if the system supports the minimum requirements,
                 otherwise, return PLUGIN_SKIP
        """
        # Check if the minimum requirements are met
        if not is_python_version_supported():  # hashdb.utilities.versions
            warning("Minimum Python version requirements not met.")
            return ida_idaapi.PLUGIN_SKIP
        if not is_ida_version_supported():  # hashdb.utilities.versions
            warning("Minimum IDA version requirements not met.")
            return ida_idaapi.PLUGIN_SKIP

        # Initialize the plugin and make the plugin object (self) accessible to
        #  the global scope
        self.__core = Core(initial_setup=True)
        sys.modules["__main__"].hashdb = self

        # Signal to IDA that we agree to work with the current database
        debug("Plugin loaded successfully.")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        """
        Invoked when the plugin is called as a script file.
        @param arg: unknown size_t type
        """
        warning("Cannot execute this plugin as a script.")

    def term(self) -> None:
        """
        Invoked when IDA is unloading the plugin.
        """
        self.__core.unload()

    #--------------------------------------------------------------------------
    # Development code
    #--------------------------------------------------------------------------
    def reload(self) -> None:
        """
        Hot-reload the plugin.
        """
        debug("Attempting to reload.")

        # Unload the plugin
        self.__core.unload()

        # Decrement the reference count on self.__core
        del self.__core

        # Reload the package
        # noinspection PyTypeChecker
        importlib.reload(hashdb)

        # Create a new self.__core instance
        self.__core = Core(initial_setup=False)

    def run_tests(self, reload: bool = False) -> None:
        """
        Perform automated bug testing.
        """
        if reload:  # Should we perform a reload?
            self.reload()
        # Run the unit tests
        self.__core.run_tests_ida()
