# System packages/modules
from __future__ import absolute_import
# noinspection PyUnresolvedReferences
import logging

# IDAPython
import ida_kernwin

# HashDB
from ..config import PLUGIN_NAME

# Global logging prefix, used when logging messages
logging_prefix: str = f"[{PLUGIN_NAME}]"


# --------------------------------------------------------------------------
# Functions
# --------------------------------------------------------------------------
def info(message: str = None) -> None:
    """
    Informs the user that a warning occurred.
    @param message: the message to be displayed
    """
    # Check if the message is not empty/valid
    if message:
        logging.info(f"{logging_prefix}: {message}")  # Debugging message.
        ida_kernwin.msg(f"{logging_prefix}: {message}\n")


def warning(message: str = None, display_messagebox=False) -> None:
    """
    Informs the user that a warning occurred.
    @param message: the message to be displayed
    @param display_messagebox: whether to show a messagebox or not
    """
    # Check if the message is not empty/valid
    if message:
        logging.warning(f"{logging_prefix}: {message}")   # Debugging message.
        ida_kernwin.msg(f"{logging_prefix}: {message}\n")  # User-friendly variant.
        # Open a messagebox
        if display_messagebox:
            ida_kernwin.warning(f"{logging_prefix}: {message}")


def debug(message: str = None) -> None:
    """
    Logs a debug message.
    @param message: the message to be logged
    """
    logging.debug(f"{logging_prefix}: {message}")  # Debugging message.
