# System packages/modules
from typing import NamedTuple


class Algorithm(NamedTuple):
    """
    Interface for a hash algorithm.
    """
    name: str  # algorithm name
    size: int  # algorithm size
