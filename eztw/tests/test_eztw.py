import pytest

import subprocess
import ctypes
import struct
import time

from .. import EztwController, EztwConsumer, get_provider, get_provider_config, parse_event, add_manual_provider
from ..guid import GUID, canonize_GUID
from ..common import FILETIME_EPOCH_DELTA_S, FILETIME_TO_SECONDS_MULTIPLIER, SYSTEMTIME
from ..trace_common import EVENT_FIELD_INTYPE, EventMetadata, EventFieldMetadata
from ..log import disable_logging


class TestEztw:

    def test_process_provider(self):
        disable_logging()
        provider = get_provider("microsoft-windows-kernel-process")
        config = get_provider_config(provider.Event_ProcessStart_1)
        session_name = "test_eztw_session"
        found_process = False
        with EztwController(session_name, config):
            with EztwConsumer(session_name) as ezc:
                new_process = subprocess.Popen("notepad")
                event_records = ezc.wait_for_events(5)
                for event_record in event_records:
                    if event_record.provider_guid != provider.guid or\
                            event_record.id != provider.Event_ProcessStart_1.id:
                        continue
                    parsed_event = parse_event(event_record)
                    if parsed_event.ProcessID == new_process.pid and\
                            "notepad" in parsed_event.ImageName.lower():
                        found_process = True
                        break
                new_process.kill()
        assert found_process

    @pytest.mark.parametrize("is_64bit", [True, False])
    def test_data_consumer(self, is_64bit):
        provider_guid = canonize_GUID("{03020100-0504-0706-0809-0a0b0c0d0e0f}")
        provider_name = "test_provider"
        field_names_types_and_values = [
            ("field_unicode_string", EVENT_FIELD_INTYPE.INTYPE_UNICODESTRING, "test unicode string"),
            ("field_ansi_string", EVENT_FIELD_INTYPE.INTYPE_ANSISTRING, b"test ansi string"),
            ("field_int8", EVENT_FIELD_INTYPE.INTYPE_INT8, -1),
            ("field_uint8", EVENT_FIELD_INTYPE.INTYPE_UINT8, 1),
            ("field_int16", EVENT_FIELD_INTYPE.INTYPE_INT16, -1000),
            ("field_uint16", EVENT_FIELD_INTYPE.INTYPE_UINT16, 1000),
            ("field_int32", EVENT_FIELD_INTYPE.INTYPE_INT32, -1000000),
            ("field_uint32", EVENT_FIELD_INTYPE.INTYPE_UINT32, 1000000),
            ("field_int64", EVENT_FIELD_INTYPE.INTYPE_INT64, -1000000000),
            ("field_uint64", EVENT_FIELD_INTYPE.INTYPE_UINT64, 1000000000),
            ("field_float", EVENT_FIELD_INTYPE.INTYPE_FLOAT, -123.456),
            ("field_double", EVENT_FIELD_INTYPE.INTYPE_DOUBLE, 123456.789),
            ("field_boolean", EVENT_FIELD_INTYPE.INTYPE_BOOLEAN, True),
            ("field_guid", EVENT_FIELD_INTYPE.INTYPE_GUID, provider_guid),
            ("field_pointer", EVENT_FIELD_INTYPE.INTYPE_POINTER, 123456789),
            ("field_filetime", EVENT_FIELD_INTYPE.INTYPE_FILETIME, 1234567890),
            ("field_systemtime", EVENT_FIELD_INTYPE.INTYPE_SYSTEMTIME, 1234567890.0),
            ("field_countedstring", EVENT_FIELD_INTYPE.INTYPE_COUNTEDSTRING, "test 123"),
            ("field_countedansistring", EVENT_FIELD_INTYPE.INTYPE_COUNTEDANSISTRING, b"test 123"),
        ]
        event_fields = [EventFieldMetadata(fname, ftype) for fname, ftype, _ in field_names_types_and_values]

        # Special cases
        binary_data1 = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09"
        event_fields.append(EventFieldMetadata("field_binary1", EVENT_FIELD_INTYPE.INTYPE_BINARY, len(binary_data1)))
        binary_data2 = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
        event_fields.append(EventFieldMetadata("field_binary2_size", EVENT_FIELD_INTYPE.INTYPE_UINT16))
        event_fields.append(EventFieldMetadata("field_binary2", EVENT_FIELD_INTYPE.INTYPE_BINARY, "field_binary2_size"))
        multi_data1 = [1, 2, 3]
        event_fields.append(EventFieldMetadata("field_multi1_count", EVENT_FIELD_INTYPE.INTYPE_UINT16))
        event_fields.append(EventFieldMetadata("field_multi1", EVENT_FIELD_INTYPE.INTYPE_UINT32, None, "field_multi1_count"))
        multi_data2 = ["qwe", "asd", "zxc"]
        event_fields.append(EventFieldMetadata("field_multi2_count", EVENT_FIELD_INTYPE.INTYPE_UINT16))
        event_fields.append(
            EventFieldMetadata("field_multi2", EVENT_FIELD_INTYPE.INTYPE_UNICODESTRING, None, "field_multi2_count"))
        multi_data3 = [b"qwer", b"asdf", b"zxcv"]
        event_fields.append(EventFieldMetadata("field_multi3_count", EVENT_FIELD_INTYPE.INTYPE_UINT16))
        event_fields.append(
            EventFieldMetadata("field_multi3", EVENT_FIELD_INTYPE.INTYPE_BINARY, 4, "field_multi3_count"))
        multi_data4 = ["qwer", "asdf", "zxcv"]
        event_fields.append(EventFieldMetadata("field_multi4_count", EVENT_FIELD_INTYPE.INTYPE_UINT16))
        event_fields.append(
            EventFieldMetadata("field_multi4", EVENT_FIELD_INTYPE.INTYPE_UNICODESTRING, 4, "field_multi4_count"))

        provider_keywords = {}

        # Define a new event template
        event_id = 1234
        event_version = 56
        provider_events = [EventMetadata(provider_guid, event_id, event_version, "test_event", 0, event_fields)]

        add_manual_provider(provider_guid, provider_name, provider_keywords, provider_events)
        provider = get_provider(provider_guid)
        event = provider.get_events_by_ids(event_id)[0]

        dummy_data_parts = []
        for _, ftype, fvalue in field_names_types_and_values:
            if ftype is EVENT_FIELD_INTYPE.INTYPE_UNICODESTRING:
                dummy_data_parts.append(bytes(ctypes.create_unicode_buffer(fvalue)))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_ANSISTRING:
                dummy_data_parts.append(bytes(ctypes.create_string_buffer(fvalue)))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_INT8:
                dummy_data_parts.append(struct.pack("b", fvalue))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_UINT8:
                dummy_data_parts.append(struct.pack("B", fvalue))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_INT16:
                dummy_data_parts.append(struct.pack("<h", fvalue))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_UINT16:
                dummy_data_parts.append(struct.pack("<H", fvalue))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_INT32:
                dummy_data_parts.append(struct.pack("<i", fvalue))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_UINT32:
                dummy_data_parts.append(struct.pack("<I", fvalue))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_INT64:
                dummy_data_parts.append(struct.pack("<q", fvalue))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_UINT64:
                dummy_data_parts.append(struct.pack("<Q", fvalue))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_FLOAT:
                dummy_data_parts.append(struct.pack("f", fvalue))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_DOUBLE:
                dummy_data_parts.append(struct.pack("d", fvalue))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_BOOLEAN:
                dummy_data_parts.append(struct.pack("<I", int(fvalue)))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_BINARY:
                dummy_data_parts.append(fvalue)
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_GUID:
                dummy_data_parts.append(bytes(GUID(fvalue)))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_POINTER:
                if is_64bit:
                    dummy_data_parts.append(struct.pack("<Q", fvalue))
                else:
                    dummy_data_parts.append(struct.pack("<I", fvalue))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_FILETIME:
                if fvalue > 0:
                    fvalue = int((fvalue + FILETIME_EPOCH_DELTA_S) / FILETIME_TO_SECONDS_MULTIPLIER)
                dummy_data_parts.append(struct.pack("<Q", fvalue))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_SYSTEMTIME:
                ts = time.localtime(fvalue)
                st = SYSTEMTIME()
                st.wYear = ts.tm_year
                st.wMonth = ts.tm_mon
                st.wDayOfWeek = ts.tm_wday
                st.wDay = ts.tm_mday
                st.wHour = ts.tm_hour
                st.wMinute = ts.tm_min
                st.wSecond = ts.tm_sec
                st.wMilliseconds = 0
                dummy_data_parts.append(bytes(st))
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_COUNTEDSTRING:
                dummy_data_parts.append(struct.pack("<H", len(fvalue)*2) + bytes(ctypes.create_unicode_buffer(fvalue))[:-2])
            elif ftype is EVENT_FIELD_INTYPE.INTYPE_COUNTEDANSISTRING:
                dummy_data_parts.append(struct.pack("<H", len(fvalue)) + bytes(ctypes.create_string_buffer(fvalue))[:-1])

        # Special cases
        dummy_data_parts.append(binary_data1)
        dummy_data_parts.append(struct.pack("<H", len(binary_data2)))
        dummy_data_parts.append(binary_data2)
        dummy_data_parts.append(struct.pack("<H", len(multi_data1)))
        for x in multi_data1:
            dummy_data_parts.append(struct.pack("<I", x))
        dummy_data_parts.append(struct.pack("<H", len(multi_data2)))
        for x in multi_data2:
            dummy_data_parts.append(bytes(ctypes.create_unicode_buffer(x)))
        dummy_data_parts.append(struct.pack("<H", len(multi_data3)))
        for x in multi_data3:
            dummy_data_parts.append(x)
        dummy_data_parts.append(struct.pack("<H", len(multi_data4)))
        for x in multi_data4:
            dummy_data_parts.append(bytes(ctypes.create_unicode_buffer(x))[:-2])

        class DummyEventRecord:
            pass

        dummy_event_record = DummyEventRecord()
        dummy_event_record.is_64bit = is_64bit
        dummy_event_record.provider_guid = provider_guid
        dummy_event_record.id = event_id
        dummy_event_record.version = event_version
        dummy_event_record.data = b''.join(dummy_data_parts)

        parsed_event = event.parse(dummy_event_record)

        for fname, ftype, fvalue in field_names_types_and_values:
            parsed_value = getattr(parsed_event, fname)
            # Annoying Python strings
            if ftype in [EVENT_FIELD_INTYPE.INTYPE_ANSISTRING, EVENT_FIELD_INTYPE.INTYPE_COUNTEDANSISTRING]:
                parsed_value = parsed_value.encode()
            elif ftype in [EVENT_FIELD_INTYPE.INTYPE_FLOAT, EVENT_FIELD_INTYPE.INTYPE_DOUBLE]:
                parsed_value = round(parsed_value, 3)
            assert(parsed_value == fvalue)

        # Special cases
        assert parsed_event.field_binary1 == binary_data1
        assert parsed_event.field_binary2 == binary_data2
        assert parsed_event.field_multi1 == multi_data1
        assert parsed_event.field_multi2 == multi_data2
        assert parsed_event.field_multi3 == multi_data3
        assert parsed_event.field_multi4 == multi_data4
