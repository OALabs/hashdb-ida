# System packages/modules
from typing import NamedTuple


class Hash(NamedTuple):
    """
    Interface for a hash object.
    """
    hash: int              # hash value
    string: str            # hashed string
    is_api: bool           # True if the hash is an API
    permutation_type: str  # type of permutation
    api: str               # hashed API string
    modules: tuple[str]    # a tuple of module strings associated to the hash
