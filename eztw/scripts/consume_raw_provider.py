"""
This is a useful script that can consume any provider based on its GUID and optional keywords
(defaults to MAX_KEYWORDS). Events are not parsed, but rather their event records are printed
and also their hex data (using the hexdump module, if it's installed, or binascii.hexlify otherwise).
"""
import sys
import time

from .. import EztwController, EztwConsumer
from ..trace_common import ad_hoc_session_name, MAX_KEYWORDS, MSNT_SystemTrace_GUID, LOST_EVENTS_GUID
from ..provider import EztwProviderConfig
from ..guid import GUID
from ..log import LOGGER

try:
    # Optional better printing using the hexdump module
    import hexdump
    print_hexdump = hexdump.hexdump
except ImportError:
    import binascii

    def print_hexdump(data):
        print(binascii.hexlify(data, ' '))

def main():
    if len(sys.argv) < 2:
        print(f"USAGE: {sys.argv[0]} [provider GUID] <hex keywords, default is 0xffffffffffffffff>")
        sys.exit(1)
    provider_guid = sys.argv[1]
    if not GUID.verify(provider_guid):
        raise ValueError(f"Invalid GUID value {provider_guid!r}")
    if len(sys.argv) > 2:
        keywords = int(sys.argv[2], 16)
    else:
        keywords = MAX_KEYWORDS
    config = EztwProviderConfig(provider_guid, keywords)
    session_name = ad_hoc_session_name()
    LOGGER.info(f"Consuming events from {provider_guid} with keywords {hex(keywords)} - press Ctrl+C to stop")
    with EztwController(session_name, config):
        for i, event_record in enumerate(EztwConsumer(session_name)):
            print(f"=== [Event {i}] {time.ctime(event_record.timestamp)} ===")
            if event_record.provider_guid == MSNT_SystemTrace_GUID:
                print("<SYSTEM TRACE EVENT>")
            elif event_record.provider_guid == LOST_EVENTS_GUID:
                print("<LOST EVENT>")
            else:
                print(event_record)
                print_hexdump(event_record.data)

if __name__ == "__main__":
    main()
