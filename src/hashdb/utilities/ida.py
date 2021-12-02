# System packages/modules
import re
from enum import IntEnum, auto as enum_auto
import struct

# IDAPython
import ida_name
import ida_enum
import ida_bytes
import ida_diskio
import ida_idaapi
import ida_typeinf

# HashDB
from ..types.enum_value import EnumValue
from ..exceptions import Exceptions


class DataType(IntEnum):
    """Used for type-safe conversions between IDA types."""
    QWORD = enum_auto()
    DWORD = enum_auto()
    FLOAT = enum_auto()
    WORD = enum_auto()
    BYTE = enum_auto()
    ARRAY = enum_auto()
    UNKNOWN = enum_auto()


ida_type_conversion_list: dict = {
    "__int64": DataType.QWORD,
    "int": DataType.DWORD,
    "float": DataType.FLOAT,
    "__int16": DataType.WORD,
    "char": DataType.BYTE
}


def get_user_directory_path() -> str:
    """
    Returns the IDA user directory path usually located at:
      - $HOME/.idapro
      - %APPDATA%Hex-Rays/IDA Pro
    @return: the user directory path
    """
    return ida_diskio.get_user_idadir()


# Name checks
def has_invalid_characters(name: str) -> bool:
    """
    Checks if a name contains invalid characters.
    @param name: a string
    @return: True if all the characters in the name are valid,
             False if one of the characters is invalid
    """
    return ida_name.is_ident(name)


def get_invalid_characters(name: str):
    """
    Finds the position of all invalid characters in a given name.
    @param name: a string
    @return: a tuple of invalid character indices
    """
    # Check if the name is empty
    if not name:
        return ()  # return an empty tuple

    invalid_character_indices: list = []

    # Check if the first character is a digit;
    #  names cannot begin with a digit
    if name[0].isdigit():
        invalid_character_indices.append(0)

    # Check all the characters to see if they're valid
    for index, character in enumerate(name):
        if not ida_name.is_ident_cp(ord(character)):
            # Append the index of the character to the list
            invalid_character_indices.append(index)

    # Return a tuple of the invalid characters indices
    return tuple(invalid_character_indices)


# Data type conversion for the commonly used types
def convert_to_qword(effective_address: int, count: int = 1, force: bool = False) -> bool:
    """
    Converts the bytes at an effective address to a QWORD.
    @param effective_address: the location of the bytes
    @param count: the amount of elements to transform
    @param force: should the conversion be forced
    @return: True if the bytes at the address were converted,
             False if the conversion failed
    """
    return ida_bytes.create_qword(effective_address, count * 8, force)


def convert_to_dword(effective_address: int, count: int = 1, force: bool = False) -> bool:
    """
    Converts the bytes at an effective address to a DWORD.
    @param effective_address: the location of the bytes
    @param count: the amount of elements to transform
    @param force: should the conversion be forced
    @return: True if the bytes at the address were converted,
             False if the conversion failed
    """
    return ida_bytes.create_dword(effective_address, count * 4, force)


def convert_to_float(effective_address: int, count: int = 1, force: bool = False) -> bool:
    """
        Converts the bytes at an effective address to a float.
        @param effective_address: the location of the bytes
        @param count: the amount of elements to transform
        @param force: should the conversion be forced
        @return: True if the bytes at the address were converted,
                 False if the conversion failed
        """
    return ida_bytes.create_float(effective_address, count * 4, force)


def convert_to_word(effective_address: int, count: int = 1, force: bool = False) -> bool:
    """
    Converts the bytes at an effective address to a WORD.
    @param effective_address: the location of the bytes
    @param count: the amount of elements to transform
    @param force: should the conversion be forced
    @return: True if the bytes at the address were converted,
             False if the conversion failed
    """
    return ida_bytes.create_word(effective_address, count * 2, force)


def convert_to_byte(effective_address: int, count: int = 1, force: bool = False) -> bool:
    """
    Converts the bytes at an effective address to a BYTE.
    @param effective_address: the location of the bytes
    @param count: the amount of elements to transform
    @param force: should the conversion be forced
    @return: True if the bytes at the address were converted,
             False if the conversion failed
    """
    return ida_bytes.create_byte(effective_address, count * 1, force)


def convert_to(effective_address: int, data_type: DataType, count: int = 1, force: bool = False) -> bool:
    """
    Convert the bytes at an effective address based on the data type provided.
    @param effective_address: the location of the bytes
    @param data_type: the data type to convert to
    @param count: the amount of elements to transform
    @param force: should the conversion be forced
    @return: True if the bytes at the address were converted,
             False if the conversion failed
    @raise: Exceptions.UnsupportedDataType: if the data type conversion is
                                            unsupported
    """
    if data_type is DataType.QWORD:
        return convert_to_qword(effective_address, count, force)
    if data_type is DataType.DWORD:
        return convert_to_dword(effective_address, count, force)
    if data_type is DataType.FLOAT:
        return convert_to_float(effective_address, count, force)
    if data_type is DataType.WORD:
        return convert_to_word(effective_address, count, force)
    if data_type is DataType.BYTE:
        return convert_to_byte(effective_address, count, force)

    # Unhandled/unknown data types.
    raise Exceptions.UnsupportedDataType(
        f"Unsupported data type encountered when converting to a type: {data_type}")


# Read commonly used data types
def read_qword(effective_address: int) -> int:
    """
    Read a QWORD from the bytes at the effective address.
    @param effective_address: the location of the bytes
    @return: a 64-bit integer
    """
    return ida_bytes.get_qword(effective_address)


def read_dword(effective_address: int) -> int:
    """
    Read a DWORD from the bytes at the effective address.
    @param effective_address: the location of the bytes
    @return: a 32-bit integer
    """
    return ida_bytes.get_dword(effective_address)


def read_float(effective_address: int) -> float:
    """
    Read a single-precision floating point number
      from the bytes at the effective address.
    @param effective_address: the location of the bytes
    @return: a single-precision floating point number
    """
    value = read_dword(effective_address)
    [float_value] = struct.unpack("f", struct.pack("I", value))
    return float_value


def read_word(effective_address: int) -> int:
    """
    Read a WORD from the bytes at the effective address.
    @param effective_address: the location of the bytes
    @return: a 16-bit integer
    """
    return ida_bytes.get_word(effective_address)


def read_byte(effective_address: int) -> int:
    """
    Read a BYTE from the bytes at the effective address.
    @param effective_address: the location of the bytes
    @return: an 8-bit integer
    """
    return ida_bytes.get_byte(effective_address)


def read(effective_address: int, data_type: DataType):
    """
    Read a data type from the bytes at an effective address.
    @param effective_address: the location of the bytes
    @param data_type: the data type to read
    @return: an integer or a float based on the data type
    @raise: Exceptions.UnsupportedDataType: if the data type is unsupported
    """
    if data_type is DataType.QWORD:
        return read_qword(effective_address)
    if data_type is DataType.DWORD:
        return read_dword(effective_address)
    if data_type is DataType.FLOAT:
        return read_float(effective_address)
    if data_type is DataType.WORD:
        return read_word(effective_address)
    if data_type is DataType.BYTE:
        return read_byte(effective_address)

    # Unhandled/unknown data types.
    raise Exceptions.UnsupportedDataType(
        f"Unsupported data type reading a value: {data_type}")


# Guess a data type from the database
def guess_type(effective_address: int) -> DataType:
    """
    Guesses the type of bytes at an effective address.
    @param effective_address: the location of the bytes
    @return: a DataType enum constant based on the guessed type
    @raise: Exceptions.UnsupportedDataType: if the data type is unsupported
    """
    guessed_type: str = ida_typeinf.idc_guess_type(effective_address)

    # Check if the guessed type is an array
    if re.match(r"\w+\[(\d+)?]", guessed_type):
        return DataType.ARRAY

    try:
        return ida_type_conversion_list[guessed_type]
    except KeyError:
        raise Exceptions.UnsupportedDataType(
            f"Unsupported data type encountered when guessing a type: {guessed_type}")


# Enum helpers
def create_enum(name: str, flags: int = ida_bytes.hex_flag(), width: int = 0) -> int:
    """
    Creates a new enum in the database from a name.
    @param name: the desired name of the enum
    @param flags: enum flags (flags_t; see ida_bytes for more info)
    @param width: the width/size in bytes of the underlying enum values
    @return: an enum id (enum_t)
    @raise Exceptions.IDAPython: if creating the enum failed, or
                                 if setting the enum width failed
    """
    enum_id: int = ida_enum.add_enum(ida_idaapi.BADADDR, name, flags)

    # Check if the enum was created successfully
    if enum_id == ida_idaapi.BADADDR:
        raise Exceptions.IDAPython(f"Failed to create an enum: {enum_id=}")

    # Set the enum width
    if width:
        set_enum_width(enum_id, width)

    # Return the enum id
    return enum_id


def find_enum(name: str) -> int:
    """
    Finds an enum by name.
    @param name: name of the enum
    @return: an enum id (enum_t)
    """
    enum_id: int = ida_enum.get_enum(name)

    # Check if the enum exists
    if enum_id == ida_idaapi.BADADDR:
        raise Exceptions.IDAPython(f"Failed to find an enum by name: {name=}")

    # Return the enum id
    return enum_id


def find_or_create_enum(name: str, flags: int = ida_bytes.hex_flag(), width: int = 0) -> int:
    """
    Finds or creates an enum by name.
    @param name: (desired) name of the enum
    @param flags: enum flags (flags_t; see ida_bytes for more info)
    @param width: the width/size in bytes of the underlying enum values
    @return: an enum id (enum_t)
    @raise Exceptions.IDAPython: if creating the enum failed, or
                                 if setting the enum width failed
                                 (create_enum)
    """
    try:
        # Check if the enum exists
        return find_enum(name)
    except Exceptions.IDAPython:
        pass

    # Attempt to create the enum
    return create_enum(name, flags, width)


def set_enum_width(enum_id: int, width: int):
    """
    Sets an enum's width/size.
    @param enum_id: enum_t provided by IDA API
    @param width: the width/size in bytes of the underlying enum values
    @raise Exceptions.IDAPython: if setting the width failed
    """
    if not ida_enum.set_enum_width(enum_id, width):
        raise Exceptions.IDAPython(f"Failed to set enum width: {enum_id=}, {width=}")


def add_values_to_enum(enum_id: int, values: tuple):
    """
    Inserts a tuple of values into an enum
    @param enum_id: enum_t provided by IDA API
    @param values: a tuple of EnumValue instances
    @raise Exceptions.IDAPython: if inserting an enum value failed
    """
    enum_value: EnumValue

    # Iterate the enum values
    for enum_value in values:
        error_code = ida_enum.add_enum_member(enum_id, enum_value.name, enum_value.value)

        # Check if an error occurred
        if not error_code:
            continue

        if error_code == ida_enum.ENUM_MEMBER_ERROR_NAME:
            raise Exceptions.IDAPython("Invalid or already taken enum name: "
                                       f"{enum_id=}, "
                                       f"{enum_value=}")
        if error_code == ida_enum.ENUM_MEMBER_ERROR_VALUE:
            raise Exceptions.IDAPython("Invalid enum value, already has 256 entries: "
                                       f"{enum_id=}, "
                                       f"{enum_value=}")
        if error_code == ida_enum.ENUM_MEMBER_ERROR_ENUM:
            raise Exceptions.IDAPython(f"Invalid enum id: {enum_id=}")

        # Unknown error code
        raise Exceptions.IDAPython("Unknown error code from add_enum_member: "
                                   f"{error_code=}, "
                                   f"{enum_id=}, "
                                   f"{enum_value=}")
