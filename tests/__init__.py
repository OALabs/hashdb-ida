import re
import sys
from unittest.mock import patch, MagicMock


def setup_ida_name() -> MagicMock:
    """
    Setup the ida_name module.
    @return: the ida_name mock module
    """
    ida_name = MagicMock()

    # Functions
    def is_ident(name: str) -> bool:
        return re.match(r"^[a-zA-Z0-9_]+$", name) is not None

    def is_ident_cp(character: int) -> bool:
        return is_ident(chr(character))

    # Set the functions
    ida_name.is_ident = is_ident
    ida_name.is_ident_cp = is_ident_cp

    # Return the module
    return ida_name


def setup_ida_enum() -> MagicMock:
    """
    Setup the ida_enum module.
    @return: the ida_enum mock module
    """
    ida_enum = MagicMock()

    # Functions
    def get_enum_member_by_name(name: str) -> int:
        import ida_name
        import ida_idaapi

        # Make sure the name is valid
        if not ida_name.is_ident(name):
            return ida_idaapi.BADADDR

        # Pattern match the names
        match = re.match(r"(?P<name>[a-zA-Z_]+)(?P<index>\d+)?$", name)
        if not match:
            raise ValueError(f"Invalid name: {name=!r}")

        name = match.group("name")
        index = match.group("index")
        if index:
            index = int(index)

        # Specific check for "taken_name"
        if name.startswith("taken_name") and (not index or index < 5):
            return ida_enum.static_enum_id
        # Specific check for "missing_suffix_0"
        if name.startswith("missing_suffix") and index < 2:
            return ida_enum.static_enum_id

        # Failed to find the enum by name
        return ida_idaapi.BADADDR

    # Set the constants and functions
    ida_enum.static_enum_id = 0x1010
    ida_enum.get_enum_member_by_name = get_enum_member_by_name

    # Return the module
    return ida_enum


def setup_ida_bytes() -> MagicMock:
    """
    Setup the ida_bytes module.
    @return: the ida_bytes mock module
    """
    ida_bytes = MagicMock()

    # Functions
    def hex_flag() -> int:
        return 0x1100000

    # Set the functions
    ida_bytes.hex_flag = hex_flag

    # Return the module
    return ida_bytes


def setup_ida_diskio() -> MagicMock:
    """
    Setup the ida_diskio module.
    @return: the ida_diskio mock module
    """
    return MagicMock()


def setup_ida_idaapi() -> MagicMock:
    """
    Setup the ida_idaapi module.
    @return: the ida_idaapi mock module
    """
    ida_idaapi = MagicMock()

    # Set the constants
    ida_idaapi.BADADDR = 0xffffffffffffffff

    # Return the module
    return ida_idaapi


def setup_ida_typeinf() -> MagicMock:
    """
    Setup the ida_typeinf module.
    @return: the ida_typeinf mock module
    """
    return MagicMock()


def setup_ida_kernwin() -> MagicMock:
    """
    Setup the ida_kernwin module.
    @return: the ida_kernwin mock module
    """
    return MagicMock()


def modules() -> dict:
    return {
        "ida_name": setup_ida_name(),
        "ida_enum": setup_ida_enum(),
        "ida_bytes": setup_ida_bytes(),
        "ida_diskio": setup_ida_diskio(),
        "ida_idaapi": setup_ida_idaapi(),
        "ida_typeinf": setup_ida_typeinf(),
        "ida_kernwin": setup_ida_kernwin()
    }


patch.dict(sys.modules, modules()).start()
