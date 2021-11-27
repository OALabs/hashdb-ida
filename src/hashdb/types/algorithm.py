# System packages/modules
from dataclasses import dataclass


@dataclass
class Algorithm:
    """
    Interface for a hash algorithm.
    """
    name: str  # algorithm name
    size: int  # algorithm size
