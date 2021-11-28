# System packages/modules
from typing import NamedTuple

# HashDB
from ..exceptions import Exceptions


class Hash(NamedTuple):
    """
    Interface for a hash object.
    """
    value: int                    # hash value
    string: str                   # hashed string
    is_api: bool                  # True if the hash is an API

    # The remaining  arguments are optional
    #  (strings that aren't APIs)
    permutation_type: str = ""  # type of permutation
    api: str = ""               # hashed API string
    modules: tuple[str] = ()    # a tuple of module strings associated to the hash

    @classmethod
    def from_json(cls, data: dict):
        """
        Creates a new class instance from a dictionary
        @param data: a json object
        @return: a new class instance
        @raise Exceptions.InvalidHashObject: if a hash object is missing
                                             the "string" object
        """
        # Parse the data
        value: int = data.get("hash")
        string_object: dict = data.get("string")

        # Check if the string object is valid
        if not string_object:
            raise Exceptions.InvalidHashObject("\"string\" object doesn't exist, or is empty.", hash_object=data)

        string: str = string_object.get("string")
        is_api: bool = string_object.get("is_api")

        # If the hash is not an API, append a Hash instance,
        #  and skip resolving other properties:
        if not is_api:
            return cls(value=value, string=string, is_api=is_api)

        # Resolve the remaining properties
        permutation_type: str = string_object.get("permutation")
        api: str = string_object.get("api")
        modules: list = string_object.get("modules")

        # Append a Hash instance
        return cls(value=value, string=string, is_api=is_api,
                   permutation_type=permutation_type, api=api,
                   modules=tuple(modules))
