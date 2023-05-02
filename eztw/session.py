"""
Implementation of EztwSessionIterator, which allows easy iteration over existing session or sessions.
It automatically parses and yields the event contents along with the event records.
If multiple sessions are consumed, a separate thread is used for each of them (since it's blocking).

In addition, provides the convenience function consume_events, which handles the consumption process
end-to-end based on the given EztwEvent objects.
"""
import threading
import queue
import time
from collections import defaultdict, Counter

from .common import as_list, EztwException
from .controller import EztwController
from .provider import eztwm, get_provider_config
from .consumer import EztwConsumer
from .event import EztwEvent, EztwFilter
from .trace_common import LOST_EVENTS_GUID, ad_hoc_session_name


class EztwSessionIterator:
    """
    This class iterates over existing sessions by names - either a single session (current thread) or multiple
    sessions (each in its own thread).

    A second, optional parameter is which events to filter. This can either be None (no filter), or
    a single or a list of EztwEvent objects. Only these events will be parsed and returned.

    Finally, the session iterator automatically counts all events consumed during its operation (including
    filtered ones) and presents a neat summary by provider/event when stopped (including when stopped
    using Ctrl+C, i.e KeyboardInterrupt).

    Example usage:
    >>> session_names = ['session1', 'session2']
    >>> events_to_filter = provider.Event_123
    >>> with EztwSessionIterator(session_names, events_to_filter) as si:
    >>>     for event_record, parsed_event in si:
    >>>         # do something
    """
    def __init__(self, session_names: str | list[str], filtered_events: EztwEvent | list[EztwEvent] | None = None):
        self.session_names = as_list(session_names)
        assert len(self.session_names) >= 1
        self.event_filter = EztwFilter(filtered_events) if filtered_events else None

    @staticmethod
    def _thread_proc_consumer(session_name, event_queue, stop_signal):
        # Consume a single session and put its event records in a shared queue until the stop signal is set
        with EztwConsumer(session_name) as ezc:
            while not stop_signal.is_set():
                event_record = ezc.get_event()
                if event_record:
                    event_queue.put(event_record)

    def _consume_events(self):
        # Consume either a single session (in current thread) or multiple sessions (in separate threads)
        if len(self.session_names) == 1:
            # With a single session - consume in the same thread
            with EztwConsumer(self.session_names[0]) as ezc:
                yield from ezc
        else:
            # For multiple sessions - create a new Queue and stop signal
            event_queue = queue.Queue()
            stop_signal = threading.Event()
            # Start one consumer thread per session (ProcessTrace is blocking each thread)
            threads = [
                threading.Thread(target=self._thread_proc_consumer, args=(session_name, event_queue, stop_signal))
                for session_name in self.session_names]
            # Start the threads
            for th in threads:
                th.start()
            try:
                # Get from queue until interrupted
                while True:
                    try:
                        yield event_queue.get(timeout=0.1)
                    except queue.Empty:
                        continue
            finally:
                # Signal all threads to stop and wait for them to join
                stop_signal.set()
                for th in threads:
                    th.join()

    def __iter__(self):
        event_counter = defaultdict(Counter)
        unknown_events = set()
        start_time = time.time()
        try:
            # Main iteration loop
            for event_record in self._consume_events():
                # Count this event
                event_counter[event_record.provider_guid][event_record.id] += 1
                if self.event_filter is None or event_record in self.event_filter:
                    try:
                        # Parse and yield
                        yield event_record, eztwm.parse(event_record)
                    except EztwException as e:
                        # Only print once per event
                        if hash(event_record.provider_guid) not in unknown_events:
                            print(f"Failed to parse event {event_record} - {e}")
                            unknown_events.add(hash(event_record.provider_guid))
        except KeyboardInterrupt:
            print("\nCaught KeyboardInterrupt")
        except Exception as e:
            print(f"\nUnhandled error - {e}")
        finally:
            # If no events where consumed, there's nothing to report
            if not event_counter:
                return
            # Print a nice summary of all consumed events
            total_time = time.time() - start_time
            print(f"\nTotal events during {total_time:.2f} seconds:")
            if LOST_EVENTS_GUID in event_counter:
                lost_events = sum(event_counter.pop(LOST_EVENTS_GUID).values())
                print(f"\tLOST EVENTS ({LOST_EVENTS_GUID}): {lost_events}")
            for provider_guid, event_count in event_counter.items():
                provider_name = eztwm.get_provider_name_from_guid(provider_guid)
                print(f"\tProvider {provider_guid} ({provider_name}):")
                for eid, cnt in event_count.most_common():
                    print(f"\t\tEvent ID {eid} - {cnt}")
            print()


def consume_events(events: EztwEvent | list[EztwEvent], session_name: str | None = None):
    """
    Convenience function that automatically deducts the needed providers and keywords from the given list of
    event classes, and only yields the parsed events if they're on the list (provider GUID + event ID).
    Session name is optional, if omitted a random trace name will be used.

    This function should probably be used for most cases.

    @param events: a single EztwEvent or a list of them - only these events will be parsed and returned
    @param session_name: either a session name to use or None (default, in which case a temporary name is used)
    """
    if not session_name:
        session_name = ad_hoc_session_name()
    # Start consuming
    with EztwController(session_name, get_provider_config(events)):
        yield from EztwSessionIterator(session_name, events)
