"""
Implementation of EztwEvent which represents a single event template.
Each event may have multiple versions, each with different fields.
This class also allows parsing the context-specific contents of an event record.
"""
import struct
import ctypes
import functools
from collections import OrderedDict
from dataclasses import make_dataclass
from typing import Union, Callable

from .common import FILETIME_to_time, EztwException, as_list, sanitize_name
from .guid import GUID
from .tdh import EVENT_FIELD_INTYPE, EventMetadata
from .consumer import EventRecord


class EztwEventParseException(EztwException):
    """Represents problem parsing an event's fields"""


class FieldsReader:
    """
    Helper class for field data deserialization
    """
    def __init__(self, data: bytes, is_64bit: bool):
        self.data = data
        self.is_64bit = is_64bit
        self.cur_offset = 0

    def consume(self, size: int) -> bytes:
        """
        Read X bytes if there are enough bytes, or raise EztwEventParseException if not
        """
        if self.cur_offset + size > len(self.data):
            raise EztwEventParseException(
                f"Data out of bounds at {self.cur_offset}:{size} (data size is {len(self.data)})")
        res = self.data[self.cur_offset:self.cur_offset + size]
        self.cur_offset += size
        return res

    def consume_BYTE(self):
        return self.consume(1)[0]

    def consume_USHORT(self):
        return struct.unpack("<H", self.consume(2))[0]

    def consume_ULONG(self):
        return struct.unpack("<I", self.consume(4))[0]

    def consume_ULONGLONG(self):
        return struct.unpack("<Q", self.consume(8))[0]

    def consume_POINTER(self):
        if self.is_64bit:
            return self.consume_ULONGLONG()
        else:
            return self.consume_ULONG()

    def consume_FILETIME(self):
        return FILETIME_to_time(self.consume_ULONGLONG())

    def consume_SYSTEMTIME(self):
        # TODO: parse as SYSTEMTIME
        return self.consume(16)

    def consume_STRING(self):
        # ctypes.string_at (unlike wstring_at) returns bytes, need to decode
        res = ctypes.string_at(self.data[self.cur_offset:]).decode(errors='replace')
        self.cur_offset += len(res) + 1
        return res

    def consume_WSTRING(self):
        res = ctypes.wstring_at(self.data[self.cur_offset:])
        self.cur_offset += (len(res) + 1) * 2
        return res

    def consume_BOOLEAN(self):
        return bool(self.consume_ULONG())

    def consume_FLOAT(self):
        return struct.unpack("f", self.consume(4))[0]

    def consume_DOUBLE(self):
        return struct.unpack("d", self.consume(8))[0]

    def consume_SID(self):
        # https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid
        # TODO: parse further?
        part1 = self.consume(2 + 6)
        part2 = self.consume(part1[1] * 4)
        return part1 + part2

    def consume_GUID(self):
        return str(GUID.from_buffer_copy(self.consume(16)))

    INTYPE_TO_CONSUMER = {
        EVENT_FIELD_INTYPE.INTYPE_INT8: consume_BYTE,
        EVENT_FIELD_INTYPE.INTYPE_UINT8: consume_BYTE,
        EVENT_FIELD_INTYPE.INTYPE_INT16: consume_USHORT,
        EVENT_FIELD_INTYPE.INTYPE_UINT16: consume_USHORT,
        EVENT_FIELD_INTYPE.INTYPE_INT32: consume_ULONG,
        EVENT_FIELD_INTYPE.INTYPE_UINT32: consume_ULONG,
        EVENT_FIELD_INTYPE.INTYPE_HEXINT32: consume_ULONG,
        EVENT_FIELD_INTYPE.INTYPE_INT64: consume_ULONGLONG,
        EVENT_FIELD_INTYPE.INTYPE_UINT64: consume_ULONGLONG,
        EVENT_FIELD_INTYPE.INTYPE_HEXINT64: consume_ULONGLONG,
        EVENT_FIELD_INTYPE.INTYPE_POINTER: consume_POINTER,
        EVENT_FIELD_INTYPE.INTYPE_BOOLEAN: consume_BOOLEAN,
        EVENT_FIELD_INTYPE.INTYPE_FILETIME: consume_FILETIME,
        EVENT_FIELD_INTYPE.INTYPE_SYSTEMTIME: consume_SYSTEMTIME,
        EVENT_FIELD_INTYPE.INTYPE_UNICODESTRING: consume_WSTRING,
        EVENT_FIELD_INTYPE.INTYPE_ANSISTRING: consume_STRING,
        EVENT_FIELD_INTYPE.INTYPE_FLOAT: consume_FLOAT,
        EVENT_FIELD_INTYPE.INTYPE_DOUBLE: consume_DOUBLE,
        EVENT_FIELD_INTYPE.INTYPE_SID: consume_SID,
        EVENT_FIELD_INTYPE.INTYPE_GUID: consume_GUID,
    }

    def consumer_by_type(self, in_type: EVENT_FIELD_INTYPE):
        consumer = self.INTYPE_TO_CONSUMER.get(in_type)
        if consumer is None:
            raise EztwEventParseException(f"Unknown IN_TYPE {in_type!r}")
        return functools.partial(consumer, self)


class EztwEvent:
    """
    Represents a single event of a provider.
    Maintains all known versions of this event and allows easy parsing.
    Each version has its own dataclass (called EventTemplate or EventTemplate_#name#).
    """
    def __init__(self, event_descriptors: list[EventMetadata]):
        # This instance is initialized from a list of TdhEvent descriptors, so for sanity
        # make sure there's at least one, and they all share the same provider GUID, id, name and keyword
        assert(len(event_descriptors) >= 1)
        self.provider_guid = event_descriptors[0].provider_guid
        assert(all(ed.provider_guid == self.provider_guid for ed in event_descriptors))
        self.id = event_descriptors[0].id
        assert (all(ed.id == self.id for ed in event_descriptors))
        self.name = event_descriptors[0].name
        assert (all(ed.name == self.name for ed in event_descriptors))
        self.keyword = 0
        # Sort the descriptors by their version, and create a template for their parsed fields
        self.versions = {}
        template_name = f"EventTemplate_{self.id}" if not self.name else f"EventTemplate_{sanitize_name(self.name)}"
        for event_descriptor in event_descriptors:
            # Note that sometimes different versions of the same event have different keywords...
            # Aggregate them just to be on the safe side
            self.keyword |= event_descriptor.keyword
            self.versions[event_descriptor.version] = (
                event_descriptor.fields,
                make_dataclass(template_name, [f.name for f in event_descriptor.fields])
            )

    def string_details(self) -> str:
        """
        @return: a nice representation of the event's versions and fields
        """
        res = [f"Event ID={self.id} ({self.name})"]
        for version, (fields, _template) in sorted(self.versions.items()):
            res.append(f"\tVersion {version}:")
            for field in fields:
                res.append(f"\t\t{field.name}: {field.type.name}")
        return '\n'.join(res)

    def print(self):
        print(self.string_details())

    def parse(self, event_record: EventRecord):
        """
        Given an EventRecord, find the correct template by version and parse the fields according to the schema.

        @param event_record: an EventRecord instance
        @return: the parsed field inside a dataclass template
        """
        # Sanity - verify provider GUID, ID and version
        # (usually this function is called by EztwProvider, so the parameters are already correct)
        # However, if this is called directly we need to make sure...
        assert(event_record.provider_guid == self.provider_guid)
        assert(event_record.id == self.id)
        if event_record.version not in self.versions:
            raise EztwEventParseException(f"Unknown version {event_record.version} for event "
                                          f"{event_record.id} of provider {event_record.provider_guid}")
        # Get the list of fields and the pre-created "template"
        event_fields, event_template = self.versions[event_record.version]
        # Maintain the order of the parsed fields
        field_values = OrderedDict()
        data_consumer = FieldsReader(event_record.data, event_record.is_64bit)
        for field in event_fields:
            # https://docs.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-inputtype-complextype
            # If there's a 'length' field, either read this amount of bytes (if length is int) or the variable
            # length is stored in a previous field (if length is str)
            if field.length:
                if isinstance(field.length, int):
                    length_value = field.length
                else:
                    length_value = field_values.get(field.length)
                field_values[field.name] = data_consumer.consume(length_value)
                # This is a special case - no need to read further
                continue
            consumer_function = data_consumer.consumer_by_type(field.type)
            # If there's a 'count' field, it means there's an array of values. The count may either be fixed (int)
            # or a name of a previous field that holds the count
            if field.count:
                if isinstance(field.count, int):
                    count_value = field.count
                else:
                    count_value = field_values.get(field.count)
                # Read this many times the field's type
                field_values[field.name] = [consumer_function() for _ in range(count_value)]
            else:
                # Simply read the field
                field_values[field.name] = consumer_function()
        # Cast the parsed fields, by order, into the immutable event template
        return event_template(*field_values.values())

    def __repr__(self):
        return f"{self.__class__.__name__}(id={self.id}, name={self.name!r}, " \
               f"provider_guid={self.provider_guid}, keyword={hex(self.keyword)})"

    def __hash__(self):
        """The event is uniquely identified via its provider GUID and event ID"""
        return hash((self.provider_guid, self.id))


class EztwFilter:
    """
    Simple helper class for filtering events.

    Initialize from a single EztwEvent or a list of them, then given an EventRecord, check if
    it's contained in this filter.

    Example:
    >>> # Initialize from a single EztwEvent or a list of them
    >>> ezf = EztwFilter(some_event)
    >>>
    >>> # Then, given an event record from a consumer:
    >>> if event_record in ezf:
    >>>     # Do something
    """
    def __init__(self, events: Union[EztwEvent, list[EztwEvent]]):
        self.event_hashes = {hash(event) for event in as_list(events)}

    def __contains__(self, event_record: EventRecord):
        return hash(event_record) in self.event_hashes


class EztwDispatcher:
    """
    Simple mapper from event class to a callback function.

    Initialize from a dict of: { EztwEvent: callable }
    Filtering is done similarly to EztwFilter.
    Each callable must accept two parameters - the event record and the parsed event. The parsed event
    can either be parsed manually (using the parse_event function, for example), but is more often
    returned by an EztwSessionIterator (like the one used in the consume_events function).

    The EztwDispatcher is simply invoked by calling it. If the given event record is not a part
    of the dispatcher, nothing will happen. Note that the hash of both EventRecord and EztwEvent are the
    same iff both their provider_guid and ID are the same.

    To simplify even further, use the .events member of the dispatcher as a list of events to filter
    for consume_events and EztwSessionIterator.

    Example:
    >>> # Define callback functions for the desired events
    >>> def some_callback(event_record, parsed_event):
    >>>     # Do something
    >>>
    >>> # Initialize from a list of EztwEvent and their desired callback
    >>> ezd = EztwDispatcher({some_event: some_callback, ...})
    >>>
    >>> # Then, given an event record and its parsed event (for example as yielded from consume_events):
    >>> for event_record, parsed_event in consume_events(ezd.events):
    >>>     # Call the callable (if the event is relevant, otherwise nothing happens)
    >>>     ezd(event_record, parsed_event)
    """
    def __init__(self, events_and_callbacks: dict[EztwEvent, Callable]):
        self.events = []
        self.mapping = {}
        for event, callback in events_and_callbacks.items():
            self.events.append(event)
            self.mapping[hash(event)] = callback

    def __call__(self, event_record: EventRecord, parsed_event):
        dispatch = self.mapping.get(hash(event_record))
        if dispatch:
            dispatch(event_record, parsed_event)
