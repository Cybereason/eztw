"""
This is a useful script that can consume any locally registered provider directly from command-line.
It automatically parses any registered events and allows easy exploration of trace providers.

If only specific events are desired, provide them as the last parameter as a comma-separated list of IDs.
Otherwise (default) all the provider's events are consumed.

For example, to consume any process/thread start events:

python -m eztw.scripts.consume_provider microsoft-windows-kernel-process 1,3
"""
import sys
import time
import contextlib

from .. import get_provider, consume_events
from ..log import LOGGER

def main():
    if len(sys.argv) < 2:
        print(f"USAGE: {sys.argv[0]} [provider name or GUID] <event ids, comma-separated>")
        sys.exit(1)
    provider = get_provider(sys.argv[1])
    if len(sys.argv) > 2:
        event_ids = list(set(map(int, sys.argv[2].split(','))))
        events = provider.get_events_by_ids(event_ids)
    else:
        # Consume all provider's events
        events = provider.events
    LOGGER.info(f"Consuming {len(events)} events from {provider.guid} - press Ctrl+C to stop")
    with contextlib.suppress(KeyboardInterrupt):
        for i, (event_record, parsed_event) in enumerate(consume_events(events)):
            print(f"=== [Event {i}] {time.ctime(event_record.timestamp)} ===")
            print(event_record)
            print(parsed_event)

if __name__ == "__main__":
    main()
