# System packages/modules
from dataclasses import dataclass


@dataclass
class EnumValue:
    name: str     # enum member unique name
    value: int    # integer value
    is_api: bool  # API function names are handled differently when adding the enums
