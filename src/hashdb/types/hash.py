# System packages/modules
from typing import NamedTuple

# HashDB
from ..exceptions import Exceptions


class Hash(NamedTuple):
    """Interface for a hash object."""
    value: int                    # hash value
    string: str                   # hashed string
    is_api: bool                  # True if the hash is an API

    # The remaining  arguments are optional
    #  (strings that aren't APIs)
    permutation_type: str = ""     # type of permutation
    api: str = ""                  # hashed API string
    modules: tuple = ()  # a tuple of module strings associated to the hash

    @classmethod
    def from_json(cls, json: dict):
        """
        Creates a new class instance from a json object (dict)
        @param json: a json object (dict)
        @return: a new class instance
        @raise Exceptions.InvalidHash: if a hash object is invalid
        """
        try:
            value: int = json["hash"]
            string_object: dict = json["string"]
            string_value: str = string_object["string"]
            is_api: bool = string_object["is_api"]

            # If the hash is not an API, append a Hash instance,
            #  and skip resolving other properties:
            if not is_api:
                return cls(value=value, string=string_value, is_api=is_api)

            # Resolve the remaining properties, and check their values
            permutation_type: str = string_object["permutation"]
            api_value: str = string_object["api"]
            modules: list = string_object["modules"]

            # Check to make sure the api value and modules are valid
            if api_value is not string_value:
                raise Exceptions.InvalidHash("Raw string and API string mismatch.", hash_object=json)
            if not modules:
                raise Exceptions.InvalidHash("Missing modules.", hash_object=json)
        except KeyError as exception:
            raise Exceptions.InvalidHash(f"Missing key: {exception.args[0]}", hash_object=json)

        # Return a Hash instance
        return cls(value=value, string=string_value, is_api=is_api,
                   permutation_type=permutation_type, api=api_value,
                   modules=tuple(modules))
