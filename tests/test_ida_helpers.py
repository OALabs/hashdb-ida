from hashdb.utilities.ida import prepare_enum_values


def test_prepare_enum_values(enum_values, expected_enum_values):
    """Simulate preparing specific enum values."""
    received_values = prepare_enum_values(enum_values)
    assert len(received_values) == len(expected_enum_values)
    for expected, received in zip(expected_enum_values, received_values):
        assert expected == received
