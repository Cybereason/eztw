"""
Various trace-specific common stuff.
"""
import ctypes
import time
from enum import Enum
from dataclasses import dataclass

from .guid import canonize_GUID

# Represents a trace handle
TRACEHANDLE = ctypes.c_uint64

# This indicates an invalid trace handle
INVALID_TRACE_HANDLE = 0xffffffffffffffff

# Many functions are required from this DLL
ADVAPI32_DLL = ctypes.windll.advapi32

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletrace
TRACE_LEVEL_CRITICAL = 1
TRACE_LEVEL_ERROR = 2
TRACE_LEVEL_WARNING = 3
TRACE_LEVEL_INFORMATION = 4
TRACE_LEVEL_VERBOSE = 5

MSNT_SystemTrace_GUID = canonize_GUID("{68fdd900-4a3e-11d1-84f4-0000f80464e3}")

# This special GUID indicates lost events
# https://learn.microsoft.com/en-us/windows/win32/etw/lost-event
LOST_EVENTS_GUID = canonize_GUID("{6a399ae0-4bc6-4de9-870b-3657f8947e7e}")


# https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-decoding_source
class PROVIDER_DECODING_SOURCE(Enum):
    DecodingSourceXMLFile = 0
    DecodingSourceWbem = 1
    DecodingSourceWPP = 2
    DecodingSourceTlg = 3
    DecodingSourceMax = 4


# https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-_tdh_in_type
class EVENT_FIELD_INTYPE(Enum):
    INTYPE_NULL = 0
    INTYPE_UNICODESTRING = 1
    INTYPE_ANSISTRING = 2
    INTYPE_INT8 = 3
    INTYPE_UINT8 = 4
    INTYPE_INT16 = 5
    INTYPE_UINT16 = 6
    INTYPE_INT32 = 7
    INTYPE_UINT32 = 8
    INTYPE_INT64 = 9
    INTYPE_UINT64 = 10
    INTYPE_FLOAT = 11
    INTYPE_DOUBLE = 12
    INTYPE_BOOLEAN = 13
    INTYPE_BINARY = 14
    INTYPE_GUID = 15
    INTYPE_POINTER = 16
    INTYPE_FILETIME = 17
    INTYPE_SYSTEMTIME = 18
    INTYPE_SID = 19
    INTYPE_HEXINT32 = 20
    INTYPE_HEXINT64 = 21
    INTYPE_MANIFEST_COUNTEDSTRING = 22
    INTYPE_MANIFEST_COUNTEDANSISTRING = 23
    INTYPE_RESERVED24 = 24
    INTYPE_MANIFEST_COUNTEDBINARY = 25
    INTYPE_COUNTEDSTRING = 26
    INTYPE_COUNTEDANSISTRING = 27
    INTYPE_REVERSEDCOUNTEDSTRING = 28
    INTYPE_REVERSEDCOUNTEDANSISTRING = 29
    INTYPE_NONNULLTERMINATEDSTRING = 30
    INTYPE_NONNULLTERMINATEDANSISTRING = 31
    INTYPE_UNICODECHAR = 32
    INTYPE_ANSICHAR = 33
    INTYPE_SIZET = 34
    INTYPE_HEXDUMP = 35
    INTYPE_WBEMSID = 36

# For those sneaky undocumented ones, keep the max known value
EVENT_FIELD_INTYPE_MAX_VALUE = max([x.value for x in EVENT_FIELD_INTYPE.__members__.values()])


@dataclass
class ProviderMetadata:
    """
    Represents the metadata of a single provider - guid, name and "decoding source" (usually XML schema)
    """
    guid: str
    name: str
    schema: PROVIDER_DECODING_SOURCE


@dataclass
class EventFieldMetadata:
    """
    Represents a single event's field - name, type and optional length/count fields
    """
    name: str
    type: EVENT_FIELD_INTYPE
    # Either the name of the field that holds the byte size of this field, or None
    length: str | int | None = None
    # Either the name of the field that holds the count of this fild, or None
    count: str | int | None = None


@dataclass
class EventMetadata:
    """
    Represents a single event - provider GUID, ID, version, name (optional), keyword and a list of TdhEventField
    """
    provider_guid: str
    id: int
    version: int
    name: str
    keyword: int
    fields: list[EventFieldMetadata]

def ad_hoc_session_name():
    return f"EZTW_TRACE_SESSION_{int(time.time())}"
