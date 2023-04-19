"""
This demo scripts starts a new trace session to consume the Microsoft-Windows-DNS-Client provider,
then in a separate thread performs DNS query to python.org.

The main thread should show these events.
"""
import time
import threading
import contextlib
from socket import gethostbyname

from .. import get_provider, get_provider_config, parse_event, EztwController, EztwConsumer, EztwFilter
from ..log import LOGGER

def delayed_dns_query(delay, name):
    LOGGER.info(f"Thread started, sleeping for {delay} seconds...")
    time.sleep(delay)
    LOGGER.info(f"Thread performing query for {name!r}")
    gethostbyname(name)

def main():
    provider = get_provider("microsoft-windows-dns-client")
    # provider = get_provider("{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}")

    session_name = "eztw_demo_dns"

    # This is the event we want according to the schema
    # https://github.com/repnz/etw-providers-docs/blob/d5f68e8acda5da154ab44e405b610dd8c2ba1164/Manifests-Win10-18990/Microsoft-Windows-DNS-Client.xml
    provider_config = get_provider_config(provider.Event_3008)
    with contextlib.suppress(KeyboardInterrupt):
        # Create a new session
        with EztwController(session_name, provider_config):
            # Schedule a separate thread for the query
            dns_delay = 3  # Seconds
            dns_query = "python.org"
            LOGGER.info(f"Starting new thread. Querying for {dns_query!r} in {dns_delay} seconds...")
            threading.Thread(target=delayed_dns_query, args=(dns_delay, dns_query)).start()
            # Start consuming events
            LOGGER.info(f"Waiting for events... (runs forever, press Ctrl+C to stop)")
            # Filter only theis event
            events_filter = EztwFilter(provider.Event_3008)
            with EztwConsumer(session_name) as ezc:
                for event_record in ezc:
                    # Skip any irrelevant event records
                    if event_record not in events_filter:
                        continue
                    # Parsed fields of event 3008:
                    #   QueryName: str
                    #   QueryType: int
                    #   QueryOptions: int
                    #   QueryStatus: int
                    #   QueryResults: str
                    parsed_event = parse_event(event_record)
                    # Print only queries performed to this domain (python.org)
                    if dns_query in parsed_event.QueryName:
                        print(f"Process PID {event_record.process_id} performed DNS query:")
                        print(parsed_event)

if __name__ == "__main__":
    main()
