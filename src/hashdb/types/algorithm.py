# System packages/modules
from dataclasses import dataclass

# HashDB
from ..exceptions import Exceptions


@dataclass
class Algorithm:
    """
    Interface for a hash algorithm.
    """
    name: str         # name
    description: str  # description
    size: int         # size (in bits)

    @classmethod
    def from_json(cls, json: dict):
        """
        Created a new class instance from a json object (dict)
        @param json: a json object (dict)
        @return: a new class instance
        @raise Exceptions.InvalidAlgorithm: if any of the required keys are missing
        @raise Exceptions.UnknownAlgorithmType: if the algorithm type is unknown
        """
        try:
            name: str = json["algorithm"]
            description: str = json["description"]
            size: int = parse_algorithm_type(json["type"])
        except KeyError as exception:
            raise Exceptions.InvalidAlgorithm(f"Missing key: {exception.args[0]}")

        # Return an Algorithm instance
        return cls(name=name, description=description, size=size)


def parse_algorithm_type(algorithm_type: str) -> int:
    """
    Converts an algorithm type into its equivalent
      size in bits.
    @param algorithm_type: type of the algorithm
    @return: size of the algorithm in bits
    @raise Exceptions.UnknownAlgorithmType: if the algorithm type is unknown
    """
    predetermined_sizes = {
        "unsigned_int":  32,
        "unsigned_long": 64
    }

    # Check if the algorithm type is a valid type
    if algorithm_type not in predetermined_sizes.keys():
        raise Exceptions.UnknownAlgorithmType(f"Unknown algorithm type encountered: {algorithm_type}",
                                              algorithm_type=algorithm_type)

    # Return the size of the algorithm
    return predetermined_sizes[algorithm_type]
