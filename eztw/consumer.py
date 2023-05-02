"""
Implementation of EztwConsumer, which allows consuming real time event records from an existing
real-time trace session.
"""
import ctypes
import queue
import time
import threading
import win32api
import winerror

from .log import LOGGER
from .guid import GUID
from .common import UCHAR, USHORT, ULONG, LPWSTR, LARGE_INTEGER, ULARGE_INTEGER, LPVOID, LONG, WCHAR, FILETIME, \
    FILETIME_to_time, EztwException, SYSTEMTIME
from .trace_common import ADVAPI32_DLL, TRACEHANDLE, INVALID_TRACE_HANDLE


class EztwConsumerException(EztwException):
    """A trace consumer error"""


########
# WINAPI

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilea
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_header
class EVENT_TRACE_HEADER_CLASS(ctypes.Structure):
    _fields_ = [('Type', UCHAR),
                ('Level', UCHAR),
                ('Version', USHORT)]

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_header
class EVENT_TRACE_HEADER(ctypes.Structure):
    _fields_ = [('Size', USHORT),
                ('HeaderType', UCHAR),
                ('MarkerFlags', UCHAR),
                ('Class', EVENT_TRACE_HEADER_CLASS),
                ('ThreadId', ULONG),
                ('ProcessId', ULONG),
                ('TimeStamp', LARGE_INTEGER),
                ('Guid', GUID),
                ('ClientContext', ULONG),
                ('Flags', ULONG)]

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace
class EVENT_TRACE(ctypes.Structure):
    _fields_ = [('Header', EVENT_TRACE_HEADER),
                ('InstanceId', ULONG),
                ('ParentInstanceId', ULONG),
                ('ParentGuid', GUID),
                ('MofData', LPVOID),
                ('MofLength', ULONG),
                ('ClientContext', ULONG)]

# https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor
class EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [('Id', USHORT),
                ('Version', UCHAR),
                ('Channel', UCHAR),
                ('Level', UCHAR),
                ('Opcode', UCHAR),
                ('Task', USHORT),
                ('Keyword', ULARGE_INTEGER)]

# https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
class EVENT_HEADER(ctypes.Structure):
    _fields_ = [('Size', USHORT),
                ('HeaderType', USHORT),
                ('Flags', USHORT),
                ('EventProperty', USHORT),
                ('ThreadId', ULONG),
                ('ProcessId', ULONG),
                ('TimeStamp', ULARGE_INTEGER),
                ('ProviderId', GUID),
                ('EventDescriptor', EVENT_DESCRIPTOR),
                ('KernelTime', ULONG),
                ('UserTime', ULONG),
                ('ActivityId', GUID)]

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-etw_buffer_context
class ETW_BUFFER_CONTEXT(ctypes.Structure):
    _fields_ = [('ProcessorNumber', UCHAR),
                ('Alignment', UCHAR),
                ('LoggerId', USHORT)]

# https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header_extended_data_item
class EVENT_HEADER_EXTENDED_DATA_ITEM(ctypes.Structure):
    _fields_ = [('Reserved1', USHORT),
                ('ExtType', USHORT),
                ('Reserved2', ULONG),
                ('DataSize', USHORT),
                ('DataPtr', ULARGE_INTEGER)]

# https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record
class EVENT_RECORD(ctypes.Structure):
    _fields_ = [('EventHeader', EVENT_HEADER),
                ('BufferContext', ETW_BUFFER_CONTEXT),
                ('ExtendedDataCount', USHORT),
                ('UserDataLength', USHORT),
                ('ExtendedData', ctypes.POINTER(EVENT_HEADER_EXTENDED_DATA_ITEM)),
                ('UserData', LPVOID),
                ('UserContext', LPVOID)]

class TIME_ZONE_INFORMATION(ctypes.Structure):
    _fields_ = [('Bias', LONG),
                ('StandardName', WCHAR * 32),
                ('StandardDate', SYSTEMTIME),
                ('StandardBias', LONG),
                ('DaylightName', WCHAR * 32),
                ('DaylightDate', SYSTEMTIME),
                ('DaylightBias', LONG)]

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-trace_logfile_header
class TRACE_LOGFILE_HEADER(ctypes.Structure):
    _fields_ = [('BufferSize', ULONG),
                ('MajorVersion', UCHAR),
                ('MinorVersion', UCHAR),
                ('SubVersion', UCHAR),
                ('SubMinorVersion', UCHAR),
                ('ProviderVersion', ULONG),
                ('NumberOfProcessors', ULONG),
                ('EndTime', LARGE_INTEGER),
                ('TimerResolution', ULONG),
                ('MaximumFileSize', ULONG),
                ('LogFileMode', ULONG),
                ('BuffersWritten', ULONG),
                ('StartBuffers', ULONG),
                ('PointerSize', ULONG),
                ('EventsLost', ULONG),
                ('CpuSpeedInMHz', ULONG),
                ('LoggerName', LPWSTR),
                ('LogFileName', LPWSTR),
                ('TimeZone', TIME_ZONE_INFORMATION),
                ('BootTime', LARGE_INTEGER),
                ('PerfFreq', LARGE_INTEGER),
                ('StartTime', LARGE_INTEGER),
                ('ReservedFlags', ULONG),
                ('BuffersLost', ULONG)]

# This must be "forward declared", because of the EVENT_TRACE_BUFFER_CALLBACK definition...
class EVENT_TRACE_LOGFILE(ctypes.Structure):
    pass

# The type for event trace callbacks.
EVENT_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(EVENT_TRACE))
EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(EVENT_RECORD))
EVENT_TRACE_BUFFER_CALLBACK = ctypes.WINFUNCTYPE(ULONG, ctypes.POINTER(EVENT_TRACE_LOGFILE))

class EVENT_CALLBACK_UNION(ctypes.Union):
    _fields_ = [('EventCallback', EVENT_CALLBACK),
                ('EventRecordCallback', EVENT_RECORD_CALLBACK)]

EVENT_TRACE_LOGFILE._fields_ = [
    ('LogFileName', LPWSTR),
    ('LoggerName', LPWSTR),
    ('CurrentTime', LARGE_INTEGER),
    ('BuffersRead', ULONG),
    ('ProcessTraceMode', ULONG),
    ('CurrentEvent', EVENT_TRACE),
    ('LogfileHeader', TRACE_LOGFILE_HEADER),
    ('BufferCallback', EVENT_TRACE_BUFFER_CALLBACK),
    ('BufferSize', ULONG),
    ('Filled', ULONG),
    ('EventsLost', ULONG),
    ('EventCallback', EVENT_CALLBACK_UNION),
    ('IsKernelTrace', ULONG),
    ('Context', LPVOID)]

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew
OpenTrace = ctypes.WINFUNCTYPE(
    TRACEHANDLE,                            # Return type
    ctypes.POINTER(EVENT_TRACE_LOGFILE),    # PEVENT_TRACE_LOGFILEW Logfile
)(("OpenTraceW", ADVAPI32_DLL))

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
ProcessTrace = ctypes.WINFUNCTYPE(
    ULONG,                          # Return type
    ctypes.POINTER(TRACEHANDLE),    # PTRACEHANDLE HandleArray,
    ULONG,                          # ULONG HandleCount
    ctypes.POINTER(FILETIME),       # LPFILETIME StartTime
    ctypes.POINTER(FILETIME),       # LPFILETIME EndTime
)(("ProcessTrace", ADVAPI32_DLL))

# https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-closetrace
CloseTrace = ctypes.WINFUNCTYPE(
    ULONG,          # Return type
    TRACEHANDLE,    # TRACEHANDLE TraceHandle
)(("CloseTrace", ADVAPI32_DLL))


########
# Eztw

class EventRecord:
    """
    A single ETW event record, with header fields shared by all ETW events.
    """
    def __init__(self, event_record: EVENT_RECORD, is_64bit: bool):
        self.is_64bit = is_64bit
        header = event_record.contents.EventHeader
        descriptor = header.EventDescriptor
        self.provider_guid = str(header.ProviderId)
        # Old-style events have their actual ID in the 'opcode' field for some reason
        self.id = descriptor.Id if descriptor.Id > 0 else descriptor.Opcode
        self.version = descriptor.Version
        self.keywords = descriptor.Keyword
        self.process_id = header.ProcessId
        self.thread_id = header.ThreadId
        # Sometimes the TimeStamp is 0 - prevent weird behavior for negative timestamps
        self.timestamp = FILETIME_to_time(header.TimeStamp) if header.TimeStamp > 0 else 0
        # Read event data
        if event_record.contents.UserData:
            self.data = ctypes.string_at(event_record.contents.UserData, event_record.contents.UserDataLength)
        else:
            self.data = bytes()

    def __str__(self):
        return f"{self.__class__.__name__}(provider_guid={self.provider_guid}, id={self.id}, " \
               f"version={self.version}, process_id={self.process_id}, timestamp={time.ctime(self.timestamp)})"

    __repr__ = __str__

    def __hash__(self):
        """The event is uniquely identified via its provider GUID and event ID"""
        return hash((self.provider_guid, self.id))


class EztwConsumer:
    """
    Real-time consumer of an existing ETW trace.
    Simply provider an existing session name.
    """
    def __init__(self, session_name: str):
        self.session_handle = None
        self.session_name = session_name
        self._buffer_callback = EVENT_TRACE_BUFFER_CALLBACK(self._buffer_callback)
        #self._event_callback = EVENT_CALLBACK(self._event_callback) # Old format, unsupported
        self._event_record_callback = EVENT_RECORD_CALLBACK(self.event_record_callback)
        # Bitness is unknown at first - assume 32 (will be set after OpenTrace is called)
        self.is_64bit = False
        self.consumer_thread = None
        # Safeguard against memory gulping if no events are consumed for a long time
        self.events_queue = queue.Queue(maxsize=1000000)
        # Since ProcessTrace is blocking, this allows to stop the trace
        self.stop_event = threading.Event()
        # Since we may want to stop either explicitly (calling stop) or implicitly (session is closed)
        # from two different threads, we must protect ourselves
        self.stop_lock = threading.Lock()
        # Keep a reference to CloseTrace, so we don't lose it in the dtor if the interpreter exits unexpectedly
        self.CloseTrace = CloseTrace

    def __del__(self):
        self.close_session()

    def open_session(self):
        # Create and initialize EVENT_TRACE_LOGFILE
        logfile = EVENT_TRACE_LOGFILE()
        logfile.LoggerName = self.session_name
        # This session must be real-time. Event records are to be consumed (i.e: "new-style", Vista and above)
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        logfile.BufferCallback = self._buffer_callback
        logfile.EventCallback.EventRecordCallback = self._event_record_callback
        # Attempt to open an existing trace session
        th = OpenTrace(ctypes.byref(logfile))
        if th == INVALID_TRACE_HANDLE:
            raise EztwConsumerException(
                f"OpenTrace failed for session {self.session_name!r} with error {win32api.GetLastError()}")
        self.session_handle = TRACEHANDLE(th)
        # Now we can determine the pointer size (though we only support 64bit for now)
        self.is_64bit = (logfile.LogfileHeader.PointerSize == 8)

    def close_session(self):
        if self.session_handle is None:
            return
        LOGGER.info(f"Closing trace consumer for session {self.session_name!r}")
        rc = self.CloseTrace(self.session_handle)
        if rc not in [winerror.ERROR_SUCCESS, winerror.ERROR_CTX_CLOSE_PENDING]:
            raise EztwConsumerException(
                f"CloseTrace failed for session {self.session_name!r} with error {rc}")
        self.session_handle = None

    def _buffer_callback(self, _buffer):
        # Basically, do nothing unless explicitly ordered to stop
        # According to https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilea
        # this if this function returns 0, the ProcessTrace loop stops
        if self.stop_event.is_set():
            return 0
        else:
            return 1

    def event_record_callback(self, event_record: EVENT_RECORD):
        # Called for each event - new format (Windows-Vista and above)
        # Drop events if queue is full
        if not self.events_queue.full():
            self.events_queue.put(EventRecord(event_record, self.is_64bit))

    def consume(self):
        try:
            # If successful, this function blocks the current thread until stopped
            rc = ProcessTrace(ctypes.byref(self.session_handle), 1, None, None)
            if rc == winerror.ERROR_WMI_INSTANCE_NOT_FOUND:
                raise EztwConsumerException(f"Session {self.session_name!r} does not exist")
            if rc != winerror.ERROR_SUCCESS:
                raise EztwConsumerException(
                    f"ProcessTrace failed for session {self.session_name!r} with error {rc}")
        finally:
            self._stop()

    def start(self):
        if self.session_handle is not None:
            return
        self.stop_event.clear()
        self.open_session()
        # Consume event in a separate thread, since ProcessTrace is blocking. Events are put in a queue
        self.consumer_thread = threading.Thread(target=self.consume, daemon=True)
        self.consumer_thread.start()

    def _stop(self):
        with self.stop_lock:
            if self.session_handle is None:
                return
            self.stop_event.set()
            self.close_session()

    def stop(self):
        self._stop()
        self.consumer_thread.join()

    def pending_events(self) -> int:
        """
        @return: number of currently pending event records
        """
        return self.events_queue.qsize()

    def get_event(self, timeout: float = 0.1) -> EventRecord | None:
        """
        Wait for the next event record up to timeout

        @param timeout: timeout in seconds
        @return: EventRecord or None (on timeout)
        """
        try:
            return self.events_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def wait_for_events(self, how_long: float) -> list[EventRecord]:
        """
        Read all currently available events and optionally wait some more for new events

        @param how_long: time to wait in seconds
        @return: list of EventRecord
        """
        start_time = time.time()
        events = []
        while (remaining_time := (start_time + how_long - time.time())) > 0:
            try:
                events.append(self.events_queue.get(timeout=remaining_time))
            except queue.Empty:
                break
        return events

    def __iter__(self):
        """
        Iterate over all events forever (or until stopped).
        If the session is externally closed (for example, using the logman.exe tool), the iteration stops.
        """
        while True:
            if self.stop_event.is_set():
                break
            event_record = self.get_event()
            if event_record is not None:
                yield event_record

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
