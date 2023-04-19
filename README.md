# Eztw &mdash; Easy Python wrapper for ETW
[![EZTW CI](https://github.com/Cybereason/eztw/actions/workflows/ci.yml/badge.svg)](https://github.com/Cybereason/eztw/actions/workflows/ci.yml)

## Table of Contents  
+ [Overview](#what-is-it)
  + [Known limitations](#known-limitations) 
+ [Usage](#usage)
  + [Trace providers and event templates](#trace-providers-and-event-templates)
  + [Trace controllers and consumers](#trace-controller-and-consumer)
  + [Eztw simplified](#eztw-simplified)
  + [Event Filter and Event Dispatcher](#event-filter-and-event-dispatcher)
  + [Exploring providers and events](#exploring-providers-and-events)
  + [Manually adding new providers](#manually-adding-new-providers)
  + [Various scripts](#various-scripts)

<br />

## What is it?

**Eztw** provides a simple and intuitive way of using ETW ([Event Tracing for Windows](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-)).

While this documentation assumes some familiarity with ETW and its concepts, here's the gist of the technology:
+ **Trace providers** emit **event records**, each with its own content and context. A trace provider is any piece of code which registers as such, but can usually be found in various OS modules.
+ All event records share the same header, but their content and context are determined by the provider through a **schema** (usually an XML manifest) which describes the emitted events and their fields.
+ **Trace sessions** are created and modified by **trace controllers**. These are "channels" that determine which events to consume from which trace providers. Trace sessions are either "real-time" (i.e: can be consumed using the API) or write to files. Anyone may consume real-time sessions as long as they have the right permissions.
+ To enable a provider in a trace session, the trace controller must use **keywords**. These are simply bitmasks defined by the provider which allow to control which events are received. Some providers have multiple keywords, some are "all-or-nothing".
+ **Trace consumers** are processes which consume events from a trace session. By using the API it's possible to receive event records. Their contents can then be parsed further according to the provider's schema. Event records will be received by the consumers about 2-3 seconds after their trigger (which makes them *near-real-time*).
+ Trace events' content fields are described by templates in the provider's schema. These hold lists of fields of several possible [types](https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-_tdh_in_type).

This whole process is very cumbersome and requires combining multiple API sets, some of them are painful to use.
The aim of the **eztw** package is to take care of all this hassle behind the scenes.
In its core, **eztw** does four things:
+ Automatically get trace provider information and event templates.
+ Control trace sessions (start, stop, enable providers).
+ Consume events from existing trace sessions.
+ Automatically parse event contents based on event templates.

### Known limitations
+ Windows 10 and above.
+ Python 3.9 and above.
+ Only real-time trace sessions supported.
+ Not all trace providers supported automatically (many undocumented providers exist, can be added manually).
+ No support (yet) for advanced features (stack-trace, kernel-side filters, etc.).

## Usage

### Trace providers and event templates

While understanding which providers and events exist is not always simple (see the section about [exploring providers and events](#exploring-providers-and-events)), once we know which events to use, the rest is easy!

Let's say we want to get events for any new process starting on the local machine.
The provider we want is [Microsoft-Windows-Kernel-Process](https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-17134/Microsoft-Windows-Kernel-Process.xml), who's GUID is {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}.
The event we want is ID=1, which is "process start" (this provider also emits events for threads, modules and more).

The first thing to do is import the function **get_provider** and use it to get the information about this specific provider.
This function allows easy access to any locally registered trace provider by GUID or by name:
```python
from eztw import get_provider
# Note that this would work as well: get_provider("Microsoft-Windows-Kernel-Process")
provider = get_provider("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")
print(provider)
# EztwProvider(guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, name='Microsoft-Windows-Kernel-Process', 26 events)
```

Note again that the GUID string is not case sensitive, and neither are the provider names.
Internally, **eztw** converts spaces and hyphens in provider names to underscores, so "Microsoft-Windows-Kernel-Process" is equivalent to "microsoft_windows kernel_process".

```python
assert get_provider("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}") is \
       get_provider("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716") is \
       get_provider("Microsoft-Windows-Kernel-Process") is \
       get_provider("microsoft_windows kernel process")
```

The **EztwProvider** instance keeps all the information required to start consuming and parsing events from the associated trace provider.
It also holds multiple **EztwEvent** instances, each containing information about the fields and different versions of a single event, and allows parsing the contents of event records which match these templates.
The EztwProvider instance has a member for each event, all named using the following convention:
```
Event_#name#_#id# (if event name exists)
Event_#id# (if no event name exists)
```

It's possible to get a dictionary of all the events instances, by member name:
```python
provider.events_by_name
# {'Event_ProcessStart_1': EztwEvent(id=1, name='ProcessStart', provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keyword=0x10),
#  'Event_ProcessStop_2': EztwEvent(id=2, name='ProcessStop', provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keyword=0x10),
#  'Event_ThreadStart_3': EztwEvent(id=3, name='ThreadStart', provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keyword=0x20),
#  'Event_ThreadStop_4': EztwEvent(id=4, name='ThreadStop', provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keyword=0x20),
#  'Event_ImageLoad_5': EztwEvent(id=5, name='ImageLoad', provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keyword=0x40),
#  'Event_ImageUnload_6': EztwEvent(id=6, name='ImageUnload', provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keyword=0x40),
#  ...
```

There it is - event ID 1 called "ProcessStart". Next we'll want to consume it and parse it.
```python
provider.Event_ProcessStart_1
# EztwEvent(id=1, name='ProcessStart', provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keyword=0x10)
```

To print the versions and fields of an **EztwEvent** simply use the **print** method:
```python
provider.Event_ProcessStart_1.print()
# Event ID=1 (ProcessStart)
#   Version 0:
#       ProcessID: INTYPE_UINT32
#       CreateTime: INTYPE_FILETIME
#       ParentProcessID: INTYPE_UINT32
#       ...
```

To get a simple list of all EztwEvent objects of the provider, simply access its *events* member:
```python
provider.events
# [EztwEvent(id=1, name='ProcessStart', provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keyword=0x10),
#  EztwEvent(id=2, name='ProcessStop', provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keyword=0x10),
#  EztwEvent(id=3, name='ThreadStart', provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keyword=0x20),
#  ...
```

It's also possible to easily get EztwEvent objects by their IDs:
```python
provider.get_events_by_ids(1)
# [EztwEvent(id=1, name='ProcessStart', provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keyword=0x10)]

provider.get_events_by_ids([12, 15])
# [EztwEvent(id=12, name='ProcessFreeze', provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keyword=0x200),
#  EztwEvent(id=15, name='ProcessRundown', provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keyword=0x10)]
```

Note that not all providers have such a clean and straight-forward list of events.
Some are obscure and poorly documented, with less meaningful event names.
Some do not have any locally registered description, but can be added manually (see relevant [section](#manually-adding-new-providers)).

### Trace controller and consumer

Let's create a new session and consume it.
One of the ways of doing so is using the **EztwController** and **EztwConsumer** classes (not that there are even [easier ways](#eztw-simplified)!).

To start a new session we need two things:
+ A name for the session (*coming up with a good session name is often the hard part!*).
+ A list of zero-or-more trace provider configuration to enable, each consisting of:
  + The provider's GUID.
  + Keyword bitmask for all desired events (indicates which events to filter).
  + Verbosity level (defaults to TRACE_LEVEL_VERBOSE, the most verbose).

We can set them manually, of course, using the **EztwProviderConfig** dataclass (but there are easier ways): 

```python
from eztw.provider import EztwProviderConfig

config = EztwProviderConfig(provider.guid, provider.Event_ProcessStart_1.keyword)
print(config)
# EztwProviderConfig(guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keywords=16, level=5)
```

Now we can create a new trace session using EztwController, then start consuming event records (unparsed, for now) using EztwConsumer:

```python
from eztw import EztwController, EztwConsumer

session_name = "a_good_session_name"
# Create a new session and enable the given providers
with EztwController(session_name, config):
    # Consume the created session
    with EztwConsumer(session_name) as ezc:
        # Iterate over the consumer to get event records in near-real-time
        for event_record in ezc:
            print(event_record)
```

Notes:
+ **EztwController** accepts either a single instance of **EztwProviderConfig**, or a list of them when multiple trace providers are to be consumed in the same session.
+ If a trace session of that name already exists, **EztwController** attempts to stop it and start a new session to replace it.
+ **EztwConsumer** is iterable and yields **EventRecord** objects. When iterated, it runs forever (or until the session is externally closed, or pressing Ctrl+C). There are other, non-blocking ways of consuming events.
+ Instead of using the 'with' syntax, it's possible to manually call the **start** and **stop** methods of both controller and consumer.
+ If a trace session is stopped externally (for example using the *logman.exe* tool), the iteration will stop automatically.
+ It's also possible to consume a pre-existing session (without closing it at the end, of course).
+ There are easier ways of getting the configuration parameters and consuming the trace session (keep reading!).

```python
# Side-note about logging: various parts of eztw use the same logging.Logger for verbosity.
# These can be turned off at any time (and re-enabled in a similar way):
from eztw.log import disable_logging, enable_logging, LOGGER
LOGGER.info("visible1")
disable_logging()
LOGGER.info("hidden")
enable_logging()
LOGGER.info("visible2")
```

Now let's start a new process - a few seconds later **EventRecord** begin to appear:

```
EventRecord(provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, id=1, version=3, process_id=22824, timestamp=Thu Mar 23 19:46:07 2023)
EventRecord(provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, id=1, version=3, process_id=40844, timestamp=Thu Mar 23 19:46:07 2023)
EventRecord(provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, id=2, version=2, process_id=40844, timestamp=Thu Mar 23 19:46:07 2023)
EventRecord(provider_guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, id=2, version=2, process_id=43272, timestamp=Thu Mar 23 19:46:07 2023)
```

**EventRecord** objects have properties that are shared by all ETW events (see [EVENT_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record)).
These include:
+ provider_guid: GUID
+ id: int
+ version: int (each version can have different fields)
+ keywords: int (the provider-defined bitmask which filtered this event)
+ process_id: int (source process of this event)
+ thread_id: int (source thread of this event)
+ timestamp: float (FILETIME converted to Python time)
+ data: bytes (the yet unparsed content of the event)

By themselves, they are not very interesting - they contain only metadata.
Note that we get not only events of ID=1, which we wanted, but also events of ID=2 (ProcessStop) which we didn't.
That's because these two events share the same *keyword*, as defined by this provider.
It's easy to filter only the desired events, as will be shown later.
The data itself is inside the **.data** member, which needs to be parsed according to the correct event template.   

We can use the **EztwEvent** object to filter and parse the contents (note that there are easier ways of doing this).
Let's add some code to the previous example:

```python
with EztwController(session_name, config):
    with EztwConsumer(session_name) as ezc:
        for event_record in ezc:
            # Skip events other than ID=1
            if event_record.provider_guid != provider.guid or\
               event_record.id != provider.Event_ProcessStart_1.id:
                continue
            # Manually use the correct EztwEvent to parse the fields
            parsed_event = provider.Event_ProcessStart_1.parse(event_record)
            print(parsed_event)
```

Now let's start another process (notepad.exe, in this case), and a few seconds later a parsed event template is printed:

```
EventTemplate_ProcessStart(ProcessID=21476, ProcessSequenceNumber=585171, CreateTime=1679585379.6605988, ParentProcessID=17344,
ParentProcessSequenceNumber=452330, SessionID=1, Flags=0, ProcessTokenElevationType=3, ProcessTokenIsElevated=0,
MandatoryLabel=b'\x01\x01\x00\x00\x00\x00\x00\x10\x00 \x00\x00', ImageName='\\Device\\HarddiskVolume4\\Windows\\System32\\notepad.exe',
ImageChecksum=228225, TimeDateStamp=109848115, PackageFullName='', PackageRelativeAppId='')
```

This *dataclass* already contains all the parsed fields of the event, based on the correct version template, and can be used as-is.
The same is true for any other event of a locally registered trace provider - they can be parsed automatically (yet efficiently) and used with the same field names described in the provider's schema.

```python
print(f"PID: {parsed_event.ProcessID} path: {parsed_event.ImageName}")
# PID: 21476 path: \Device\HarddiskVolume4\Windows\System32\notepad.exe
```

In the next section we'll see easier ways to consume and parse events and iterate sessions.

Note that the iteration over **EztwConsumer** objects will continue forever (or until Ctrl+C, or if the session is stopped externally, or if you call the EztwConsumer.stop() method for this consumer in a separate thread).
However, simply iterating events forever in a loop is not always the desired use-case.

With a **EztwConsumer** object it's also possible to use the following functions to get the next event or collect events in a given time period:

```python
with EztwController(session_name, config):
    with EztwConsumer(session_name) as ezc:
        # Get the current number of events ready to be consumed
        print(f"There are currently {ezc.pending_events()} pending events")
        # Wait for the next event until timeout (returns None on timeout)
        print(f"Trying to get next event or until timeout: {ezc.get_event(timeout=5)}")
        # Aggregate all events until timeout and return them as a list of EventRecords
        print("Collecting events for a few seconds...")
        event_records = ezc.wait_for_events(timeout=5)
        print(f"Collected {len(event_records)} events")
```

### Eztw simplified

As promised, there are much easier ways of consuming and parsing events!

First, while using the **EztwEvent** object itself to parse event record data is a perfectly reasonable thing to do, it does requires to locate the correct provider and event template in advance.
Instead, we can use the function **parse_event** which does everything behind the scenes:

```python
from eztw import parse_event

parse_event(event_records[0])
```

This function automatically identifies the trace provider (by GUID), fetches its event templates if these are not already cached, and parses the correct version of the event template!

Remember the **EztwProviderConfig** we manually created to enable provider in a new trace session? Instead, it's possible get the config directly from the interesting events using the function **get_provider_config**:
```python
from eztw import get_provider_config

get_provider_config([provider.Event_ProcessStart_1, provider.Event_ThreadStart_3, provider.Event_ImageLoad_5])
# [EztwProviderConfig(guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keywords=112, level=5)]
```

This function returns a list which can be passed as-is to **EztwController** to enable these providers and events.
Of course, it's possible to enable and consume events from multiple providers at the same time:

```python
provider2 = get_provider("microsoft_windows_kernel_file") 
config2 = get_provider_config([provider.Event_ProcessStart_1, provider2.Event_CreateNewFile_30])
config2
# [EztwProviderConfig(guid={22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, keywords=16, level=5),
#  EztwProviderConfig(guid={edd08927-9cc4-4e65-b970-c2560fb5c289}, keywords=4096, level=5)]

with EztwController(session_name, config2):
    ...
```

Now let's revisit and expand the first scenario - we want to consume the ProcessStart event, parse it and print to screen whenever a new *notepad.exe* process is started.

Instead of using any of the previously described classes, it's possible to simply use the **consume_events** function, which receives a single **EztwEvent** or a list of them and handles everything automagically!
It's also possible to provide a name for the created session, though a default one can be used (the default format is 'EZTW_TRACE_SESSION_#TIMESTAMP#').
Note that it uses the **get_provider_config** and **parse_event** functions under the hood:

```python
from eztw import consume_events
import time

# consume_events yields pairs of (EventRecord, EventTemplate)
for event_record, parsed_event in consume_events([provider.Event_ProcessStart_1]):
    # Filter only events for newly started notepads
    if "notepad.exe" in parsed_event.ImageName.lower():
        print(f"{time.ctime(event_record.timestamp)} new notepad.exe started with PID {parsed_event.ProcessID}")
```

The **consume_events** function does several things:
+ Gets the provider configuration using **get_provider** and **get_provider_config**.
+ Creates a new session using **EztwController**.
+ Starts consuming events using **EztwConsumer** from the created session.
+ Filters only the requested events, ignoring others.
+ Parses all requested events and returns them in addition to the event record.

Additionally, there's another feature - when stopping the loop using Ctrl+C (KeyboardInterrupt), instead of simply raising an ugly exception, we get a nice summary printout of all the events consumed during the operation (even the skipped ones).

This behavior is provided by the **EztwSessionIterator** class, which is used by **consume_events** but is also useful all by itself.
In addition to catching keyboard interrupts and printing a nice summary, and in addition to automatically parsing event fields, the session iterator also allows to iterate multiple sessions at the same time (whether these sessions were created by **eztw** or not).
The decision whether the session iterator consumes a single or multiple session is determined by the parameter (a single string or a list of strings).
In such cases, a separate thread is created for each trace session.
When consuming multiple sessions, the consumed events are NOT guaranteed to be ordered by the correct time.

```python
from eztw import EztwSessionIterator

# Create two separate sessions and consume them both
config2 = get_provider_config([provider2.Event_CreateNewFile_30])
with EztwController(session_name, config), EztwController("other_session", config2):
    # EztwSessionIterator yields pairs of (EventRecord, EventTemplate)
    for event_record, parsed_event in EztwSessionIterator([session_name, "other_session"]):
        print("="*20)
        print(event_record)
        print(parsed_event)
```

Now consuming any event is easy!

## Event Filter and Event Dispatcher

Two more convenience classes are **EztwFilter** and **EztwDispatcher**.
Both use the pair (provider GUID, event ID) to identify a specific **EztwEvent** instance, which can be useful for easily filtering and dispatching (i.e: calling a callback function) for consumed events.

The class **EztwFilter** is initialized from a single **EztwEvent** object or a list of them, and is then used to filter **EventRecord** instances while consuming events:

```python
from eztw import EztwFilter

# Initialize either from a single EztwEvent or a list
ezf = EztwFilter(provider.Event_ProcessStart_1)

# Now given an event_record of type EventRecord, check it in the filter:

# if event_record in ezf:
#   ...
```

**EztwDispatcher** is similar but initialized by a list of pairs of **EztwEvent** objects and their dispatched callables.
Then, given **EventRecord** instances, it can be used to dispatch the correct callable (the event record and parsed fields are passed as parameters to this function):

```python
from eztw import EztwDispatcher

def some_callback(event_record, parsed_event):
    # Do something
    print(event_record)
    print(parsed_event)

ezd = EztwDispatcher([(provider.Event_ProcessStart_1, some_callback)])

# Now given an event_record of type EventRecord and its parsed fields (parsed_event),
# call the callback function by simply passing it the event record and parsed fields:
for event_record, parsed_event in consume_events(provider.Event_ProcessStart_1):
    ezd(event_record, parsed_event)
```

If the dispatcher has no dispatcher for the given event record - it's simply ignored.

## Exploring providers and events

To get a full list of all locally registered providers, use the function **get_providers** (note: the calls to the [TDH API](https://learn.microsoft.com/en-us/windows/win32/etw/retrieving-event-data-using-tdh) are a bit expensive, so these functions' results are cached behind the scenes):

```python
from eztw import get_providers

providers = get_providers()
print(len(providers))
# 1116

providers[297]
# ({22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}, 'Microsoft-Windows-Kernel-Process')
```

This function returns only the GUIDs and names - to get the **EztwProvider** use **get_provider** as before with either the name or the GUID.

Now, given an EztwProvider, it's also possible to use its **print()** method to quickly view all events and their fields:

```python
provider = get_provider("{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}")
provider.print()
```

This will result in something similar to:

```
Event ID=1 (ProcessStart)
        Version 0:
                ProcessID (INTYPE_UINT32)
                CreateTime (INTYPE_FILETIME)
                ParentProcessID (INTYPE_UINT32)
                SessionID (INTYPE_UINT32)
                ImageName (INTYPE_UNICODESTRING)
        Version 1:
                ProcessID (INTYPE_UINT32)
                CreateTime (INTYPE_FILETIME)
                ParentProcessID (INTYPE_UINT32)
                SessionID (INTYPE_UINT32)
                Flags (INTYPE_UINT32)
                ImageName (INTYPE_UNICODESTRING)
        ...
Event ID=2 (ProcessStop)
        Version 0:
                ProcessID (INTYPE_UINT32)
                CreateTime (INTYPE_FILETIME)
                ExitTime (INTYPE_FILETIME)
                ExitCode (INTYPE_UINT32)
                TokenElevationType (INTYPE_UINT32)
                HandleCount (INTYPE_UINT32)
                CommitCharge (INTYPE_UINT64)
                CommitPeak (INTYPE_UINT64)
                ImageName (INTYPE_ANSISTRING)
        ...
```

Of course, as mentioned before, each EztwEvent also has its own **print** method:
```python
provider.Event_ImageLoad_5.print()
# Event ID=5 (ImageLoad)
#         Version 0:
#                 ImageBase: INTYPE_POINTER
#                 ImageSize: INTYPE_POINTER
#                 ProcessID: INTYPE_UINT32
#                 ImageCheckSum: INTYPE_UINT32
#                 TimeDateStamp: INTYPE_UINT32
#                 DefaultBase: INTYPE_POINTER
#                 ImageName: INTYPE_UNICODESTRING
```

*Advice: to visually explore local trace providers and their specific events, a tool such as [EtwExplorer](https://github.com/zodiacon/EtwExplorer) is recommended.*

## Manually adding new providers

While automatically fetching provider details is very convenient, sometimes it's impossible to get these details using the TDH API since the schema is unavailable (or maybe you created your own proprietary trace provider).
In such cases, it's possible to manually add a new provider using the function **add_manual_provider**.

This does mean manually constructing *each and every* field of *each and every* event, but it is only done once (and in the future might be inferred automatically from XML manifests).

Here's an example for a simple provider with a single event which has two versions:

```python
from eztw.tdh import TdhEvent, TdhEventField, TDH_INTYPE

provider_guid = "{03020100-0504-0706-0809-0a0b0c0d0e0f}"
provider_name = "My New Provider"
events = [
    # ID 123, version 0
    TdhEvent(provider_guid, 123, 0, "My event", 0x100, # Keyword
        # Fields
        [
             TdhEventField("field1", TDH_INTYPE.INTYPE_INT32),
        ]
    ),
    # ID 123, version 1
    TdhEvent(provider_guid, 123, 1, "My event", 0x100,
        [
            TdhEventField("field1", TDH_INTYPE.INTYPE_INT32),
            TdhEventField("field2", TDH_INTYPE.INTYPE_ANSISTRING),
        ]
    ),
]
```

These three parameters can then be used to add a new provider (overwriting any with an identical GUID or name in the process):

```python
from eztw import add_manual_provider

# Add a new provider and return the new EztwProvider instance
add_manual_provider(provider_guid, provider_name, events)
# EztwProvider(guid={03020100-0504-0706-0809-0a0b0c0d0e0f}, name='My New Provider', 1 events)
```

This provider is now cached and will be used for parsing events with the correct provider GUID, event IDs and versions, like any other provider:
```python
assert get_provider("my new provider") is get_provider("03020100-0504-0706-0809-0a0b0c0d0e0f")
```

## Various scripts

### **demo_dns**

*python -m eztw.scripts.demo_dns*

This script demonstrates the usage of **EztwController**, **EztwConsumer** and **EztwFilter** to consume and parse DNS events.
The script performs a delayed DNS query for *python.org*, then waits for the resulting events.

### **demo_process**

*python -m eztw.scripts.demo_process*

This script demonstrates the usage of **consume_events** and **EztwDispatcher** to track new notepad.exe processes and print any module they load.
The script performs a delayed process creation of *notepad.exe*, then waits for the resulting events.

### **demo_file**

*python -m eztw.scripts.demo_file*

This script demonstrates a fully-fledged file-event consuming infrastructure.
While the [Microsoft-Windows-Kernel-File](https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-17134/Microsoft-Windows-Kernel-File.xml) provider can be consumed just like any other, it has additional complications:
+ Event context is not always clear, and several versions of the same events exist (some defunct).
+ The first action for each operation is to open the file by path, but most events only contain a "file object" which refers to the original opened file. These need to be tracked and matched.
+ There are quite a few obscure flags that need to be understood, most of them documented in [NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).

This script tracks any activity relevant to files with "eztw_test" in their names.
It performs delayed actions on such a temporary file, then waits for the resulting events.

### **consume_provider**

*python -m eztw.scripts.consume_provider [provider name or GUID] <optional event IDs, comma separated>*

This useful script consumes the given provider, by name or GUID, and prints its parsed events to screen.
Specific events can be included via the second argument as a comma-separated value.
Otherwise, all the provider's events are consumed.
It is very useful for quickly exploring new and unknown trace providers.

### **tap_session**

*python -m eztw.scripts.tap_session [session name]*

This useful script "taps" into an existing *real-time* ETW session (assuming permissions are sufficient) and starts printing its parsed events to screen using **EztwSessionIterator**.
It is very useful to explore existing sessions and debug them.
