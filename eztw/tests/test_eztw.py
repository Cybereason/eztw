import pytest

import subprocess

from .. import EztwController, EztwConsumer, get_provider, get_provider_config, parse_event
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
