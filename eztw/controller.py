"""
Implementation of EztwController, which allows starting and stopping trace sessions, as well as
enabling providers.

Note: there are some advanced options when enabling providers (kernel-side filters, stack trace, etc.).
These are not yet supported.
"""
import ctypes
import winerror
import win32event

from .guid import GUID
from .log import LOGGER
from .common import UCHAR, ULONG, ULONGLONG, LARGE_INTEGER, ULARGE_INTEGER, LPVOID, LPWSTR, HANDLE, \
    as_list, EztwException
from .trace_common import ADVAPI32_DLL, TRACEHANDLE
from .provider import EztwProviderConfig


class EztwControllerException(EztwException):
    """A trace controller error"""


########
# WINAPI

# https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants
EVENT_TRACE_REAL_TIME_MODE = 0x00000100

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilea
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100

# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wmistr/ns-wmistr-_wnode_header
WNODE_FLAG_TRACED_GUID = 0x00020000

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracea
EVENT_TRACE_CONTROL_STOP = 1

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
ENABLE_TRACE_PARAMETERS_VERSION_2 = 2

# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wmistr/ns-wmistr-_wnode_header
class WNODE_HEADER(ctypes.Structure):
    _fields_ = [('BufferSize', ULONG),
                ('ProviderId', ULONG),
                ('HistoricalContext', ULARGE_INTEGER),
                ('TimeStamp', LARGE_INTEGER),
                ('Guid', GUID),
                ('ClientContext', ULONG),
                ('Flags', ULONG)]

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [('Wnode', WNODE_HEADER),
                ('BufferSize', ULONG),
                ('MinimumBuffers', ULONG),
                ('MaximumBuffers', ULONG),
                ('MaximumFileSize', ULONG),
                ('LogFileMode', ULONG),
                ('FlushTimer', ULONG),
                ('EnableFlags', ULONG),
                ('AgeLimit', ULONG),
                ('NumberOfBuffers', ULONG),
                ('FreeBuffers', ULONG),
                ('EventsLost', ULONG),
                ('BuffersWritten', ULONG),
                ('LogBuffersLost', ULONG),
                ('RealTimeBuffersLost', ULONG),
                ('LoggerThreadId', HANDLE),
                ('LogFileNameOffset', ULONG),
                ('LoggerNameOffset', ULONG)]

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-starttracew
StartTrace = ctypes.WINFUNCTYPE(
    ULONG,                                      # Return type
    ctypes.POINTER(TRACEHANDLE),                # PTRACEHANDLE TraceHandle
    LPWSTR,                                     # LPCSTR InstanceName
    ctypes.POINTER(EVENT_TRACE_PROPERTIES),     # PEVENT_TRACE_PROPERTIES Properties
)(("StartTraceW", ADVAPI32_DLL))

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
ControlTrace = ctypes.WINFUNCTYPE(
    ULONG,                                      # Return type
    TRACEHANDLE,                                # TRACEHANDLE TraceHandle
    LPWSTR,                                     # LPCSTR InstanceName
    ctypes.POINTER(EVENT_TRACE_PROPERTIES),     # PEVENT_TRACE_PROPERTIES Properties
    ULONG,                                      # ULONG ControlCode
)(("ControlTraceW", ADVAPI32_DLL))

# https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nc-evntprov-penablecallback
EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1

# Not supported yet...

# # https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
# class EVENT_FILTER_DESCRIPTOR(ctypes.Structure):
#     _fields_ = [('Ptr', ULARGE_INTEGER),
#                 ('Size', ULONG),
#                 ('Type', ULONG),
#                 ]
#
# # https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
# class ENABLE_TRACE_PARAMETERS(ctypes.Structure):
#     __fields__ = [("Version", ULONG),
#                   ("EnableProperty", ULONG),
#                   ("ControlFlags", ULONG),
#                   ("SourceId", GUID),
#                   ("EnableFilterDesc", ctypes.POINTER(EVENT_FILTER_DESCRIPTOR)),
#                   ("FilterDescCount", ULONG),
#                   ]

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
EnableTraceEx2 = ctypes.WINFUNCTYPE(
    ULONG,                                      # Return type
    TRACEHANDLE,                                # TRACEHANDLE TraceHandle
    ctypes.POINTER(GUID),                       # LPCGUID ProviderId
    ULONG,                                      # ULONG ControlCode
    UCHAR,                                      # UCHAR Level,
    ULONGLONG,                                  # ULONGLONG MatchAnyKeyword
    ULONGLONG,                                  # ULONGLONG MatchAllKeyword
    ULONG,                                      # Timeout
    LPVOID,                                     # PENABLE_TRACE_PARAMETERS EnableParameters (not supported yet)
    # ctypes.POINTER(ENABLE_TRACE_PARAMETERS),
)(("EnableTraceEx2", ADVAPI32_DLL))


########
# Eztw

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
class TraceProperties:
    """
    A utility class to wrap usage of the EVENT_TRACE_PROPERTIES structure.
    Currently only suitable for real-time trace session.
    """

    MAX_LOGFILENAME_LEN = 1024
    BUFFER_SIZE = (ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 2 * ctypes.sizeof(ctypes.c_wchar) * MAX_LOGFILENAME_LEN)

    def __init__(self):
        self._buf = (ctypes.c_byte * self.BUFFER_SIZE)()
        self.properties = ctypes.cast(ctypes.pointer(self._buf), ctypes.POINTER(EVENT_TRACE_PROPERTIES))
        self.properties.contents.Wnode.BufferSize = self.BUFFER_SIZE
        self.properties.contents.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        self.properties.contents.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        self.properties.contents.LogFileNameOffset = (ctypes.sizeof(EVENT_TRACE_PROPERTIES) +
                                                      ctypes.sizeof(ctypes.c_wchar) * self.MAX_LOGFILENAME_LEN)
        self.properties.contents.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        # TODO: allow customizing these values
        self.properties.contents.BufferSize = 32
        self.properties.contents.MinimumBuffers = 8


class EztwController:
    """
    Create and manage a real-time trace session, as well as enable providers by config.
    """
    def __init__(self, session_name: str, providers_config: EztwProviderConfig | list[EztwProviderConfig]):
        """
        @param session_name: the name of the new trace
        @param providers_config: a list of EztwProviderConfig or a single EztwProviderConfig
        """
        self.session_handle = None
        self.session_name = session_name
        self.providers_config = as_list(providers_config)
        assert self.providers_config  # Make sure we have at least one provider

    def __del__(self):
        self.stop()

    def start(self):
        """
        Start a new session or if one with the same name already exists - attempt to stop it first and then
        start the new session.
        """
        if self.session_handle is not None:
            return
        # Allocate a new trace handle
        trace_handle = TRACEHANDLE()
        LOGGER.info(f"Starting trace session {self.session_name!r}...")
        trace_properties = TraceProperties()
        # Call StartTrace
        rc = StartTrace(ctypes.byref(trace_handle), self.session_name, trace_properties.properties)
        if rc == winerror.ERROR_ALREADY_EXISTS:
            # This error code means a session with this name already exists - try to stop and start again
            LOGGER.warning(
                f"Session {self.session_name!r} already exists. Trying to stop and start a new session")
            trace_properties = TraceProperties()
            rc = ControlTrace(0, self.session_name, trace_properties.properties, EVENT_TRACE_CONTROL_STOP)
            if rc != winerror.ERROR_SUCCESS:
                raise EztwControllerException(
                    f"ControlTrace failed for session {self.session_name!r} with error {rc}")
            # Try again
            trace_properties = TraceProperties()
            rc = StartTrace(ctypes.byref(trace_handle), self.session_name, trace_properties.properties)
        if rc != winerror.ERROR_SUCCESS:
            raise EztwControllerException(
                f"StartTrace failed for session {self.session_name!r} with error {rc}")
        # Success!
        self.session_handle = trace_handle
        # Enable providers
        for provider_config in self.providers_config:
            LOGGER.info(f"Enabling provider {provider_config.guid} keywords={hex(provider_config.keywords)}")
            self.enable_provider(provider_config.guid, provider_config.keywords, provider_config.level)

    def stop(self):
        if self.session_handle is None:
            return
        LOGGER.info(f"Stopping trace session {self.session_name!r}")
        trace_properties = TraceProperties()
        rc = ControlTrace(self.session_handle, None, trace_properties.properties, EVENT_TRACE_CONTROL_STOP)
        if rc == winerror.ERROR_WMI_INSTANCE_NOT_FOUND:
            # Session no longer exists...
            pass
        elif rc != winerror.ERROR_SUCCESS:
            raise EztwControllerException(
                f"ControlTrace failed for session {self.session_name!r} with error {rc}")
        self.session_handle = None

    def enable_provider(self, provider_guid: str, keywords: int, level: int):
        # TODO: support filters, stack trace and other advanced features
        # etp = ENABLE_TRACE_PARAMETERS()
        # etp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2
        # etp.FilterDescCount = 0
        provider_guid_struct = GUID(provider_guid)
        rc = EnableTraceEx2(
                self.session_handle,
                ctypes.byref(provider_guid_struct),
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                level,
                keywords,
                0,
                win32event.INFINITE,
                None,  # ctypes.byref(etp),
            )
        if rc != winerror.ERROR_SUCCESS:
            raise EztwControllerException(
                f"EnableTraceEx2 failed for session {self.session_name!r} for provider {provider_guid}"
                f" with error {rc}")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
