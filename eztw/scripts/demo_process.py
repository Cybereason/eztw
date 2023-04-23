"""
Consume events for process-start, process-stop and image-load from Microsoft-Windows-Kernel-Process.
Track only processes called notepad.exe.
"""
import time
import threading
import contextlib
import subprocess

from .. import get_provider, consume_events, EztwDispatcher
from ..log import LOGGER


class ProcessTracker:
    """
    Helper class that defines our callback functions
    """
    def __init__(self):
        # Maintain a list of currently used PIDs by notepad.exe processes
        self.notepad_processes = set()

    def on_process_start(self, event_record, parsed_event):
        if "notepad.exe" in parsed_event.ImageName:
            print(f"New process (PID {parsed_event.ProcessID}) started from {parsed_event.ImageName}")
            self.notepad_processes.add(parsed_event.ProcessID)

    def on_process_stop(self, event_record, parsed_event):
        if "notepad.exe" in parsed_event.ImageName and parsed_event.ProcessID in self.notepad_processes:
            print(f"Process (PID {parsed_event.ProcessID}) stopped")
            self.notepad_processes.remove(parsed_event.ProcessID)

    def on_image_load(self, event_record, parsed_event):
        # Only print loaded modules if this is one of our "tracked" notepad PIDs
        if parsed_event.ProcessID in self.notepad_processes:
            print(f"Process {parsed_event.ProcessID} loaded a new module: {parsed_event.ImageName}")

def delayed_process(delay, name):
    LOGGER.info(f"Thread started, sleeping for {delay} seconds...")
    time.sleep(delay)
    LOGGER.info(f"Thread starting new process {name!r}")
    process = subprocess.Popen(name)
    time.sleep(delay)
    process.kill()

def main():
    provider = get_provider("microsoft windows kernel process")
    # provider = get_provider("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")

    process_tracker = ProcessTracker()
    # Initialize EztwDispatcher that maps from the desired events to their callbacks
    events_dispatcher = EztwDispatcher({
        provider.Event_ProcessStart_1: process_tracker.on_process_start,
        provider.Event_ProcessStop_2: process_tracker.on_process_stop,
        provider.Event_ImageLoad_5: process_tracker.on_image_load,
    })

    # Create a delayed thread that starts and stops a new notepad.exe
    process_delay = 3  # Seconds
    process_name = "notepad.exe"
    LOGGER.info(f"Starting new thread. Launching {process_name!r} in {process_delay} seconds...")
    threading.Thread(target=delayed_process, args=(process_delay, process_name)).start()

    LOGGER.info(f"Waiting for events... (runs forever, press Ctrl+C to stop)")
    with contextlib.suppress(KeyboardInterrupt):
        # Consuming and dispatching events is easy!
        # Note that events_dispatcher has an 'events' member that holds all registered events
        for event_record, parsed_event in consume_events(events_dispatcher.events):
            events_dispatcher(event_record, parsed_event)

if __name__ == "__main__":
    main()
