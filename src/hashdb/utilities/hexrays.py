def is_hexrays_module_available() -> bool:
    """
    Checks if the Hex-Rays decompiler is available.
    @return: True if the Hex-Rays decompiler is available,
             False otherwise.
    """
    try:
        import ida_hexrays  # noqa: F401
        return True
    except ImportError:
        return False


def is_hexrays_decompiler_available() -> bool:
    """
    Checks if the Hex-Rays decompiler is available.
    @return: True if the Hex-Rays decompiler is available,
             False otherwise.
    """
    try:
        import ida_hexrays
        return ida_hexrays.init_hexrays_plugin()
    except ImportError:
        return False
