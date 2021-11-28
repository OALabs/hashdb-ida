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
    def from_json(cls, json: dict):
        """
        Creates a new class instance from a json object (dict)
        @param json: a json object (dict)
        @return: a new class instance
        @raise Exceptions.InvalidHash: if a hash object is invalid
        """
        # Parse the data
        value: int = json.get("hash")
        if value is None:  # None
            raise Exceptions.InvalidHash("Missing hash value.", hash_object=json)
        string_object: dict = json.get("string")
        if not string_object:  # None or empty
            raise Exceptions.InvalidHash("Invalid \"string\" object.", hash_object=json)

        string_value: str = string_object.get("string")
        if not string_value:  # None or empty string
            raise Exceptions.InvalidHash("Invalid string value.", hash_object=json)
        is_api: bool = string_object.get("is_api")
        if is_api is None:
            raise Exceptions.InvalidHash("Missing is_api value.", hash_object=json)

        # If the hash is not an API, append a Hash instance,
        #  and skip resolving other properties:
        if not is_api:
            return cls(value=value, string=string_value, is_api=is_api)

        # Resolve the remaining properties, and check their values
        permutation_type: str = string_object.get("permutation")
        if not permutation_type:  # None or empty string
            raise Exceptions.InvalidHash("Invalid permutation type.", hash_object=json)
        api: str = string_object.get("api")
        if not api or api != string_value:  # None or empty string or api != string
            raise Exceptions.InvalidHash("Invalid api name, or api doesn't match the raw string.",
                                         hash_object=json)
        modules: list = string_object.get("modules")
        if not modules or not len(modules):  # None or empty list
            raise Exceptions.InvalidHash("Missing modules.", hash_object=json)

        # Return a Hash instance
        return cls(value=value, string=string_value, is_api=is_api,
                   permutation_type=permutation_type, api=api,
                   modules=tuple(modules))
