# System packages/modules
from typing import NamedTuple


class EnumValue(NamedTuple):
    name: str     # enum member unique name
    value: int    # integer value
    is_api: bool  # API function names are handled differently when adding the enums
