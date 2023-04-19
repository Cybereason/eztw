"""
This useful script allows to "tap" into any pre-existing real-time trace session and start consuming
and parsing its events.

For example:
python -m eztw.scripts.tap_session EventLog-System
"""
import sys
import time
import contextlib

from ..log import LOGGER
from .. import EztwSessionIterator

def main():
    if len(sys.argv) < 2:
        print(f"USAGE: {sys.argv[0]} [existing real-time session name]")
        sys.exit(1)
    LOGGER.info(f"Tapping into session {sys.argv[1]!r} - press Ctrl+C to stop")
    with contextlib.suppress(KeyboardInterrupt):
        for i, (event_record, parsed_event) in enumerate(EztwSessionIterator(sys.argv[1])):
            print(f"=== [Event {i}] {time.ctime(event_record.timestamp)} ==")
            print(event_record)
            print(parsed_event)

if __name__ == "__main__":
    main()
