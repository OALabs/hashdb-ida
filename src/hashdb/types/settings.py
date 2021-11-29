# System packages/modules
from dataclasses import dataclass

# HashDB
from .algorithm import Algorithm
from ..exceptions import Exceptions


@dataclass
class Settings:
    api_url: str          # local, global
    enum_prefix: str      # local, global
    request_timeout: int  # local, global
    algorithm: Algorithm  # local

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
