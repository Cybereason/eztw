"""
This is a useful script that can consume any provider based on its GUID and optional keywords
(defaults to 0xFFFFFFFFFFFFFFFF). Events are not parsed, but rather their event records are printed
and also their hex data (using the hexdump module, if it's installed, or binascii.hexlify otherwise).
"""
import sys
import time
import contextlib

from .. import EztwController, EztwConsumer
from ..trace_common import ad_hoc_session_name
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
        keywords = 0xFFFFFFFFFFFFFFFF
    config = EztwProviderConfig(provider_guid, keywords)
    session_name = ad_hoc_session_name()
    LOGGER.info(f"Consuming events from {provider_guid} with keywords {hex(keywords)} - press Ctrl+C to stop")
    with contextlib.suppress(KeyboardInterrupt):
        with EztwController(session_name, config):
            with EztwConsumer(session_name) as ezc:
                for i, event_record in enumerate(ezc):
                    print(f"=== [Event {i}] {time.ctime(event_record.timestamp)} ===")
                    print(event_record)
                    print_hexdump(event_record.data)

if __name__ == "__main__":
    main()
