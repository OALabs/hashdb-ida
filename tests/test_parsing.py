import pytest

from hashdb.types.algorithm import Algorithm
from hashdb.types.hash import Hash
from hashdb.types.hit import Hit
from hashdb.exceptions import Exceptions


def test_parse_valid_algorithms(valid_algorithms_data: dict):
    """Simulate parsing valid algorithm objects"""
    algorithm_data: dict
    for algorithm_data in valid_algorithms_data["algorithms"]:
        Algorithm.from_json(algorithm_data)


def test_parse_invalid_algorithms(invalid_algorithms_data: dict):
    """Simulate parsing invalid algorithm objects"""
    # Should throw an exception
    for algorithm_data in invalid_algorithms_data["algorithms"]:
        with pytest.raises(Exceptions.InvalidAlgorithm):
            Algorithm.from_json(algorithm_data)


def test_parse_valid_hashes(valid_hash_data: dict):
    """Simulate parsing valid hash objects"""
    hash_data: dict
    for index, hash_data in enumerate(valid_hash_data["hashes"]):
        hash = Hash.from_json(hash_data)
        if index == 1:  # the second entry should be a string hash without API data
            assert not hash.is_api  # is_api = False


def test_parse_invalid_hashes(invalid_hash_data: dict):
    """ Simulate parsing multiple invalid hash objects"""
    # Should throw an exception
    for hash_data in invalid_hash_data["hashes"]:
        with pytest.raises(Exceptions.InvalidHash):
            Hash.from_json(hash_data)


def test_parse_valid_hits(valid_hits_data: dict):
    """Simulate parsing valid algorithm objects"""
    for hit_data in valid_hits_data["hits"]:
        Hit.from_json(hit_data)


def test_parse_invalid_hits(invalid_hits_data: dict):
    """Simulate parsing invalid algorithm objects"""
    # Should throw an exception
    for hit_data in invalid_hits_data["hits"]:
        with pytest.raises(Exceptions.InvalidHit):
            Hit.from_json(hit_data)
