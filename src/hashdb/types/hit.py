# System packages/modules
from typing import NamedTuple


class Hit(NamedTuple):
    """
    Interface for a hash hits.
    """
    name: str       # algorithm name
    count: int      # number of hits
    hitrate: float  # hit rate
