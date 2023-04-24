"""
Implementation of EztwProvider which represents a single provider (and its events).
Implementation of EztwManager - a utility class for efficiently managing and accessing providers
by name and GUID.

In addition, multiple API functions are exposed:
    get_provider - return EztwProvider by GUID or name
    get_providers - return a list of all locally registered providers (GUIDs and names)
    get_provider_config - return the required EztwProviderConfig to enable providers based on desired events
    add_manual_provider - manually add a new, non-registered provider
    parse_event - given an EventRecord, parse it (assuming the provider and its events are known)
"""
from collections import defaultdict
from dataclasses import dataclass
from typing import Union

from .common import sanitize_name, EztwException, as_list
from .trace_common import TRACE_LEVEL_VERBOSE, MSNT_SystemTrace_GUID
from .guid import GUID, canonize_GUID
from .tdh import tdh_enumerate_providers, tdh_get_provider_events, EventMetadata, EztwTdhException
from .event import EztwEvent, EventRecord


class EztwProviderException(EztwException):
    """Indicates a missing or unknown provider"""


class EztwProvider:
    """
    Represents a trace provider and its events.
    It is constructed from GUID, name and a list of TdhEvent objects (usually done automatically by EztwManager).
    """
    def __init__(self, guid: str, name: str, event_descriptors: list[EventMetadata]):
        self.guid = str(GUID(guid))
        self.name = name
        # Group the event descriptors by their id
        by_id = defaultdict(list)
        for event_descriptor in event_descriptors:
            by_id[event_descriptor.id].append(event_descriptor)
        # Rearrange the events for ease of access
        self.events_by_id = {}
        self.events_by_name = {}
        self.all_keywords = 0
        for event_id, event_descriptors in by_id.items():
            # Add a new EztwEvent instance, store it by id and by its sanitized name
            event = EztwEvent(event_descriptors)
            self.events_by_id[event.id] = event
            if event.name:
                actual_event_name = f"Event_{sanitize_name(event.name)}_{event.id}"
            else:
                actual_event_name = f"Event_{event.id}"
            self.events_by_name[actual_event_name] = event
            setattr(self, actual_event_name, event)
            self.all_keywords |= event.keyword

    @property
    def events(self) -> list[EztwEvent]:
        return [event for _id, event in sorted(self.events_by_id.items())]

    def get_events_by_ids(self, event_ids: Union[int, list[int]]) -> list[EztwEvent]:
        return [self.events_by_id[event_id] for event_id in as_list(event_ids) if event_id in self.events_by_id]

    def parse(self, event_record: EventRecord):
        """
        Given an EventRecord (and assuming it has the correct provider GUID), attempt to parse its content
        fields based on its ID and version
        """
        # Ensure the provider GUID is correct
        assert event_record.provider_guid == self.guid
        event = self.events_by_id.get(event_record.id)
        if not event:
            raise EztwProviderException(
                f"Provider {self.guid} ({self.name}) - unknown event ID {event_record.id}")
        return event.parse(event_record)

    def string_details(self):
        """
        @return: a nice representation of the provider, including all its events
        """
        res = [f"Provider GUID={self.guid} ({self.name})", "*" * 40]
        for event in self.events:
            res.append(event.string_details(indent=1))
        return '\n'.join(res)

    def print(self):
        print(self.string_details())

    def __repr__(self):
        return f"{self.__class__.__name__}(guid={self.guid}, name={self.name!r}, {len(self.events_by_name)} events)"


@dataclass
class EztwProviderConfig:
    """
    Used to enable providers in new sessions using provider GUID, keywords and verbosity level
    """
    guid: str
    keywords: int = 0xFFFFFFFFFFFFFFFF
    level: int = TRACE_LEVEL_VERBOSE


def canonize_provider_name(provider_name: str) -> str:
    return sanitize_name(provider_name).lower()


class EztwManager:
    """
    A convenience class for retrieving and accessing providers, creating appropriate configuration to enable
    providers in trace sessions, and generic parsing of event records (by automatically finding the correct
    provider and event).

    Access to this class' methods is thread-safe.
    """
    def __init__(self):
        # This is the EztwProvider cache (starts empty)
        self.providers = {}
        # This is a tombstone for providers which were asked for but are unavailable
        # (to prevent using the TDH again for unknown providers)
        self._unknown_provider_tombstone = object()
        # Get all locally registered providers and map both from GUID to name as well as name to GUID
        self.provider_guid_by_name = {}
        self.provider_name_by_guid = {}
        for tdh_provider in tdh_enumerate_providers():
            self.provider_guid_by_name[canonize_provider_name(tdh_provider.name)] = tdh_provider.guid
            # Some GUIDs appear more than once - keep the first one (the name is not necessarily unique)
            if tdh_provider.guid in self.provider_name_by_guid:
                continue
            self.provider_name_by_guid[tdh_provider.guid] = tdh_provider.name
        # Special provider (very old kernel provider)
        self.providers[MSNT_SystemTrace_GUID] = self._unknown_provider_tombstone
        self.provider_name_by_guid[MSNT_SystemTrace_GUID] = "MSNT_SystemTrace"

    def add_manual_provider(self, provider_guid: str, provider_name: str, provider_events: list[EventMetadata]):
        new_provider = EztwProvider(provider_guid, provider_name, provider_events)
        self.providers[new_provider.guid] = new_provider
        self.provider_name_by_guid[new_provider.guid] = provider_name
        self.provider_guid_by_name[canonize_provider_name(provider_name)] = new_provider.guid
        return new_provider

    def get_provider_name_from_guid(self, provider_guid: str) -> str:
        provider_guid = canonize_GUID(provider_guid)
        return self.provider_name_by_guid.get(provider_guid) or "Unknown"

    def get_provider_by_guid(self, provider_guid: str) -> EztwProvider:
        provider_guid = canonize_GUID(provider_guid)
        provider = self.providers.get(provider_guid)
        # If the value for this GUID is a tombstone - we already know this provider is unavailable via TDH API
        if provider is self._unknown_provider_tombstone:
            raise EztwProviderException(f"Could not find events for provider {provider_guid}")
        # If the value for this GUID is cached - simply return it
        elif provider is not None:
            return provider
        # Add new provider
        provider_name = self.get_provider_name_from_guid(provider_guid)
        try:
            provider_events = tdh_get_provider_events(provider_guid)
            new_provider = EztwProvider(provider_guid, provider_name, provider_events)
            self.providers[provider_guid] = new_provider
            return new_provider
        except EztwTdhException:
            # Set a tombstone for this provider GUID, so we won't try again for the next event
            self.providers[provider_guid] = self._unknown_provider_tombstone
            raise EztwProviderException(f"Could not find events for provider {provider_guid}")

    def get_provider_by_name(self, provider_name: str) -> EztwProvider:
        provider_guid = self.provider_guid_by_name.get(canonize_provider_name(provider_name))
        if not provider_guid:
            raise EztwProviderException(f"Could not find locally registered provider named {provider_name}")
        return self.get_provider_by_guid(provider_guid)

    def get_provider(self, guid_or_name: str) -> EztwProvider:
        if GUID.verify(guid_or_name):
            return self.get_provider_by_guid(guid_or_name)
        else:
            return self.get_provider_by_name(guid_or_name)

    def parse(self, event_record: EventRecord):
        return self.get_provider_by_guid(event_record.provider_guid).parse(event_record)

    def __repr__(self):
        return f"{self.__class__.__name__}({len(self.provider_name_by_guid)} registered providers)"

#####################
# Syntactic sugaring

# Create a single global instance of the manager
eztwm = EztwManager()

def get_provider(guid_or_name: str) -> EztwProvider:
    """
    @param guid_or_name: either a provider name or a provider GUID string
    @return: EztwProvider
    """
    return eztwm.get_provider(guid_or_name)

def get_providers() -> list[(str, str)]:
    """
    @return: a list of tuples, each containing (provider GUID, provider name)
    """
    return list(eztwm.provider_name_by_guid.items())

def get_provider_config(events: Union[EztwEvent, list[EztwEvent]],
                        level: int = TRACE_LEVEL_VERBOSE) -> list[EztwProviderConfig]:
    """
    @param events: either a single EztwEvent or a list of them (not necessarily from the same provider!)
    @param level: verbosity level (0-5, default: TRACE_LEVEL_VERBOSE)
    @return: list of EztwProviderConfig, one for each relevant provider
    """
    # Rearrange events by provider GUID, and aggregate their keywords
    by_provider_guid = defaultdict(int)
    for event in as_list(events):
        by_provider_guid[event.provider_guid] |= event.keyword
    # In the special case where ALL events are required (i.e: aggregated keywords equal "all_keywords"),
    # instead set the keywords to max (0xffffffffffffffff)
    for provider_guid, keywords in list(by_provider_guid.items()):
        if keywords == eztwm.get_provider_by_guid(provider_guid).all_keywords:
            by_provider_guid[provider_guid] = 0xffffffffffffffff
    return [EztwProviderConfig(guid, keywords, level) for guid, keywords in by_provider_guid.items()]

def add_manual_provider(provider_guid: str, provider_name: str, provider_events: list[EventMetadata]):
    """
    Manually add a new provider (potentially overwriting existing one with identical GUID/name)

    @param provider_guid: GUID object
    @param provider_name: string
    @param provider_events: a list of TdhEvent objects
    """
    return eztwm.add_manual_provider(provider_guid, provider_name, provider_events)

def parse_event(event_record: EventRecord):
    """
    Parse the given event record according to its provider GUID, event ID and event version, and
    return an immutable event template containing the parsed fields.

    Note that the provider's details are automatically fetched if this is the first time it's encountered (cached).

    @param event_record: an EventRecord object
    """
    return eztwm.parse(event_record)
