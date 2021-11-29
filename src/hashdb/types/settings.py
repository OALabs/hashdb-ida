# System packages/modules
from dataclasses import dataclass

# HashDB
from .algorithm import Algorithm
from ..exceptions import Exceptions


@dataclass
class Settings:
    api_url: str          # The API URL to create requests to;                    saved: local, global
    enum_prefix: str      # The enum prefix to use when creating new enums;       saved: local, global
    request_timeout: int  # The per request timeout to use when sending requests; saved: local, global
    algorithm: Algorithm  # An algorithm instance to know which algorithm to use; saved: local

    @classmethod
    def from_json(cls, json: dict):
        """
        Creates a new class instance from a json object (dict)
        @param json: a json object (dict)
        @return: a new class instance
        @raise Exceptions.InvalidSettings: if any of the required keys are missing
        @raise Exceptions.InvalidAlgorithm: if any of the required keys are missing (Algorithm.from_json)
        """
        try:
            api_url: str = json["api_url"]
            enum_prefix: str = json["enum_prefix"]
            request_timeout: int = json["request_timeout"]
            algorithm: Algorithm = Algorithm.from_json(json["algorithm"])
        except KeyError as exception:
            raise Exceptions.InvalidSettings(f"Missing key: {exception.args[0]}", settings_object=json)

        return cls(api_url=api_url, enum_prefix=enum_prefix,
                   request_timeout=request_timeout, algorithm=algorithm)

    @classmethod
    def defaults(cls):
        """
        Constructs the default settings.
        @return: a Settings instance with default parameters
        """
        # noinspection PyTypeChecker
        return cls(api_url="https://hashdb.openanalysis.net",
                   enum_prefix="hashdb_strings",
                   request_timeout=15,
                   algorithm=None)
