"""
Implementation of GUID structure - can be constructed either from bytes (as a ctypes.Structure)
or from string of a GUID (via the ctor).
"""
import re
import ctypes


class GUID(ctypes.Structure):
    """
    Represents a Windows GUID object. Can be read from a string or directly from data.
    Can be converted back to a GUID string.
    """

    # See https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid
    _fields_ = [("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8)]

    GUID_RE = re.compile("^{?([0-9A-F]{8})-"
                         "([0-9A-F]{4})-"
                         "([0-9A-F]{4})-"
                         "([0-9A-F]{2})([0-9A-F]{2})-"
                         "([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})"
                         "([0-9A-F]{2})([0-9A-F]{2})([0-9A-F]{2})}?$",
                         re.IGNORECASE)

    @classmethod
    def verify(cls, possibly_guid_string: str) -> bool:
        """
        Verify that the given object is a valid GUID string.

        @param possibly_guid_string: a string which might be a GUID
        @return: True or False
        """
        return cls.GUID_RE.search(possibly_guid_string) is not None

    def __init__(self, guid_str: str):
        super().__init__()
        # Verify using regex that the string is valid
        guid_match = self.GUID_RE.search(guid_str)
        if guid_match is None:
            raise ValueError(f"Invalid GUID string {guid_str!r}")
        guid_parts = [int(i, 16) for i in guid_match.groups()]
        self.Data1 = guid_parts[0]
        self.Data2 = guid_parts[1]
        self.Data3 = guid_parts[2]
        for i in range(8):
            self.Data4[i] = guid_parts[3 + i]

    def __str__(self):
        d = self.Data4
        # This result is cached
        return f"{{{self.Data1:08x}-{self.Data2:04x}-{self.Data3:04x}-{d[0]:02x}{d[1]:02x}-" \
               f"{d[2]:02x}{d[3]:02x}{d[4]:02x}{d[5]:02x}{d[6]:02x}{d[7]:02x}}}"

    __repr__ = __str__
