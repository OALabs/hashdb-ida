# System packages/modules
from typing import NamedTuple

# HashDB
from ..exceptions import Exceptions


# Used for resolving algorithm types from strings and ints
algorithm_types: dict = {
    "unsigned_int": 32,
    "unsigned_long": 64,
    32: "unsigned_int",
    64: "unsigned_long"
}


class Algorithm(NamedTuple):
    """Interface for a hash algorithm."""
    name: str         # name
    description: str  # description
    size: int         # size (in bits)

    @classmethod
    def from_json(cls, json: dict):
        """
        Created a new class instance from a json object (dict)
        @param json: a json object (dict)
        @return: a new class instance
        @raise Exceptions.InvalidAlgorithm: if any of the required keys are missing, or
                                            if an invalid algorithm type is encountered (parse_algorithm_type)
        """
        try:
            name: str = json["algorithm"]
            description: str = json["description"]
            size: int = parse_algorithm_type(json["type"])
        except KeyError as exception:
            raise Exceptions.InvalidAlgorithm(f"Missing key: {exception.args[0]}")
        except Exceptions.UnknownAlgorithmType as exception:
            raise Exceptions.InvalidAlgorithm(f"Invalid algorithm type: {exception=}")

        # Return an Algorithm instance
        return cls(name=name, description=description, size=size)

    def to_json(self) -> dict:
        """
        Transform the instance to a json object.
        @return: a json object of the instance
        """
        return {
            "algorithm": self.name,
            "description": self.description,
            "type": transform_algorithm_type(self.size)
        }


def parse_algorithm_type(algorithm_type: str) -> int:
    """
    Converts an algorithm type into its equivalent size in bits.
    @param algorithm_type: type of the algorithm
    @return: size of the algorithm in bits
    @raise Exceptions.UnknownAlgorithmType: if the algorithm type is unknown
    """
    try:
        return algorithm_types[algorithm_type]
    except KeyError:
        raise Exceptions.UnknownAlgorithmType(f"Unknown algorithm type from string: {algorithm_type}")


def transform_algorithm_type(algorithm_size: int) -> str:
    """
    Converts an algorithm size (in bits) into its equivalent string.
    @param algorithm_size: size of the algorithm
    @return: a string of the algorithm type
    @raise Exceptions.UnknownAlgorithmType: if the algorithm type is unknown
    """
    try:
        return algorithm_types[algorithm_size]
    except KeyError:
        raise Exceptions.UnknownAlgorithmType(f"Unknown algorithm type from integer: {algorithm_size}")
