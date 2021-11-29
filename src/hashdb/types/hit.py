# System packages/modules
from typing import NamedTuple

# HashDB
from ..exceptions import Exceptions


class Hit(NamedTuple):
    """
    Interface for a hash hits.
    """
    algorithm: str  # algorithm name
    count: int      # number of hits
    hitrate: float  # hit rate

    @classmethod
    def from_json(cls, json: dict):
        """
        Created a new class instance from a json object (dict)
        @param json: a json object (dict)
        @return: a new class instance
        @raise Exceptions.InvalidHit: if any of the required keys are missing
        """
        try:
            algorithm: str = json["algorithm"]
            count: int = json["count"]
            hitrate: float = json["hitrate"]
        except KeyError as exception:
            raise Exceptions.InvalidHit(f"Missing key: {exception.args[0]}")

        # Return an Algorithm instance
        return cls(algorithm=algorithm, count=count, hitrate=hitrate)
