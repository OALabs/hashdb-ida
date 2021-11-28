import pytest

from hashdb.types.hash import Hash
from hashdb.exceptions import Exceptions


def test_parse_valid_hashes(valid_hash_data: dict):
    """
    Simulate parsing valid hash objects.
    """
    hash_data: dict
    for index, hash_data in enumerate(valid_hash_data["hashes"]):
        hash = Hash.from_json(hash_data)
        if index == 1:  # the second entry should be a string hash without API data
            assert not hash.is_api  # is_api = False


def test_parse_invalid_hashes(invalid_hash_data: dict):
    """
    Simulate parsing multiple invalid hash objects.
    """
    # Should throw an exception
    for hash_data in invalid_hash_data["hashes"]:
        with pytest.raises(Exceptions.InvalidHashObject):
            Hash.from_json(hash_data)
