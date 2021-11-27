# System packages/modules
from typing import NamedTuple


class Hash(NamedTuple):
    """
    Interface for a hash object.
    """
    value: int                    # hash value
    string: str                   # hashed string
    is_api: bool                  # True if the hash is an API

    # The remaining  arguments are optional
    #  (strings that aren't APIs)
    permutation_type: str = None  # type of permutation
    api: str = None               # hashed API string
    modules: tuple[str] = None    # a tuple of module strings associated to the hash
