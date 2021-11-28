import pytest


@pytest.fixture(scope="session")
def valid_hash_data():
    yield {'hashes': [{'hash': 1653273962, 'string': {'string': 'RouteTheCall', 'is_api': True,
                                                      'permutation': 'api', 'api': 'RouteTheCall',
                                                      'modules': ['zipfldr']}},
                      {'hash': 2998556761, 'string': {'string': 'DllCanUnloadNow', 'is_api': False}}]}


@pytest.fixture(scope="session")
def invalid_hash_data():
    yield {'hashes': [{'hash': 1653273962},  # missing string object
                      {'hash': 1075368562, 'string':  # missing "is_api" in the string object
                          {'string': 'DllGetClassObject'}},
                      {'hash': 1075368562, 'string':  # missing permutation value
                          {'string': 'DllGetClassObject',
                           'is_api': True}},
                      {'hash': 1075368562, 'string':  # api value != string value
                          {'string': 'DllGetClassObject',
                           'is_api': True,
                           'permutation': 'api',
                           'api': 'DllGetClassObject_12345'}},
                      {'hash': 1075368562, 'string':  # missing "modules"
                          {'string': 'DllGetClassObject',
                           'is_api': True,
                           'permutation': 'api',
                           'api': 'DllGetClassObject_12345'}}]}
