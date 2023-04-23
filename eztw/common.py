"""
Various definitions and functions used throughout eztw.
"""
import re
import ctypes.wintypes

# Simplify windows types and add some missing ones
UCHAR = ctypes.c_uint8
USHORT = ctypes.c_ushort
ULONG = ctypes.c_ulong
ULONGLONG = ctypes.c_ulonglong
LPVOID = ctypes.c_void_p
LONG = ctypes.wintypes.LONG
WCHAR = ctypes.wintypes.WCHAR
ULARGE_INTEGER = ctypes.wintypes.ULARGE_INTEGER
LARGE_INTEGER = ctypes.wintypes.LARGE_INTEGER
HANDLE = ctypes.wintypes.HANDLE
LPWSTR = ctypes.wintypes.LPWSTR
FILETIME = ctypes.wintypes.FILETIME

# The number of seconds between 01-01-1601 and 01-01-1970
FILETIME_EPOCH_DELTA_S = 11644473600
# Multiplier to convert from units of 100ns to seconds
FILETIME_TO_SECONDS_MULTIPLIER = 1.0/10000000.0

def FILETIME_to_time(ft):
    return (ft * FILETIME_TO_SECONDS_MULTIPLIER) - FILETIME_EPOCH_DELTA_S

def as_list(x):
    """
    Ensure that the returned value is a list, whether the input is a list or not
    """
    # If this is a list, simply return
    if isinstance(x, list):
        return x
    # If this object is iterable, but is not a string/bytes - convert it to list
    if hasattr(x, "__iter__") and not isinstance(x, (str, bytes, bytearray)):
        return list(x)
    # Wrap x as a list and return
    return [x]

def sanitize_name(name: str) -> str:
    """Replace invalid characters with underscores"""
    return re.sub(r"\W", "_", name)


class EztwException(Exception):
    """Generic base class for other eztw exceptions"""
