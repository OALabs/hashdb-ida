# IDAPython
import ida_bytes
import ida_diskio


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
    @param count: the amount of elements to transform to
    @param force: should the conversion be forced
    @return: True if the bytes at the address were converted,
             False if the call failed
    """
    return ida_bytes.create_qword(effective_address, count * 8, force)


def convert_to_dword(effective_address: int, count: int = 1, force: bool = False) -> bool:
    """
    Converts the bytes at an effective address to a DWORD.
    @param effective_address: the location of the bytes
    @param count: the amount of elements to transform to
    @param force: should the conversion be forced
    @return: True if the bytes at the address were converted,
             False if the call failed
    """
    return ida_bytes.create_dword(effective_address, count * 4, force)


def convert_to_word(effective_address: int, count: int = 1, force: bool = False) -> bool:
    """
    Converts the bytes at an effective address to a WORD.
    @param effective_address: the location of the bytes
    @param count: the amount of elements to transform to
    @param force: should the conversion be forced
    @return: True if the bytes at the address were converted,
             False if the call failed
    """
    return ida_bytes.create_word(effective_address, count * 2, force)


def convert_to_byte(effective_address: int, count: int = 1, force: bool = False) -> bool:
    """
    Converts the bytes at an effective address to a BYTE.
    @param effective_address: the location of the bytes
    @param count: the amount of elements to transform to
    @param force: should the conversion be forced
    @return: True if the bytes at the address were converted,
             False if the call failed
    """
    return ida_bytes.create_byte(effective_address, count * 1, force)


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
