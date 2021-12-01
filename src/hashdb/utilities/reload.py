# System packages/modules
import sys
import importlib
from types import ModuleType


def reload(module: ModuleType):
    importlib.reload(module)


def recursive_reload(module: ModuleType):
    """
    Recursively reload a module and its submodules.
    @param module: a Python module
    """
    # Filter modules that aren't associated with this module
    module_name = module.__name__

    def comparator(name: str):
        return name.startswith(module_name)

    modules = filter(comparator, tuple(sys.modules))
    for mod in modules:
        reload(sys.modules[mod])
