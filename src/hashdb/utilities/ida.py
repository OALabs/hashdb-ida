# System packages/modules
import re
from enum import IntEnum, auto as enum_auto
import struct

# IDAPython
import ida_bytes
import ida_diskio
import ida_typeinf

# HashDB
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
    Guesses the type of an effective address.
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
